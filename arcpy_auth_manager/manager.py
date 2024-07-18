"""
    A set of functionality to manage credentials to both import arcpy safely (knowing
    it will be licensed) and to
    publish to the same organization's ArcGIS Online instance.
    In short, ArcGIS has two methods - the first is a token that lasts up to a year, but
    needs to be manually rotated. The second is OAuth2 credentials that last up to two weeks,
    but can be rotated programatically (I think we should be able to do this with arcpy).

    So, this file includes functionality that, given a starting set of credentials, begins
    managing 2-week OAuth2 credentials so that they can be automatically rotated.

    IMPORTANT: This will need to persist credentials to disk - we need to do a few things
    to minimize security implications of this:
        1. It seems like we might want to use the Windows Credential Manager (accessible
        via the keyring package). keyring also provides support for some Linux-based
        credential managers if someone wanted to use some
        functionality of this package to manage ArcGIS Online credentials for publishing from
        an ArcGIS Server?
        2. It wouldn't hurt to do some kind of 2-way encryption on the stored data. Even if
        the encryption key is hardcoded here, it means that the value on disk can't be used
        as-is, which is good. We could use the username as an encryption key. If we keep
        a sqlite database somewhere, we could use the username and a timestamp or something.
        These all just incrementally obscure the credential, but they make it much
        harder for a program that gains access to the store credential to make us of.

    This all starts with an initialization value. So even if the user account this runs under
    is lost for some reason, we can set it up again with a new initialization credential (that
    immediately gets rotated by the application).

    What we also need to do is set up the rest of this codebase to rotate the key automatically
    whenever it runs, and *if* we don't run the rest of the code more than every two weeks,
    we at least need to run this. My guess is this will looks something like a daily run:
        1. to rotate the key
        2. then to check if there is a data update and run the rest of the code

    Initially, I thought that the responsibility for scheduling would get passed to the
    calling code or package, but if this will be a standalone package, it wouldn't hurt
    to have a windows task scheduler template and/or cron entries if we support Linux.

    Initial support will focus on Windows though, but leaving space for Linux support to be
    added (e.g. don't close doors that would make it hard to patch in Linux support later.
    A generic interface for handling task scheduling that's platform dependent, for example,
    feels like the right level of complexity to bother engineering in today)

"""

import sys
import os
import pathlib
import json

from typing import Any
import cryptography

import cryptography.fernet
import keyring

DEFAULT_SERVICE_NAME = "arcpy_auth_manager"

# start with an empty set of params. We'll merge in their username and their initialization key when
# it's provided
init_params:dict[str, Any] = {
    "access_token": "",
    "expires_in": 1800,
    "ssl": True,
    "username": ""
}


class TokenManager():
    _service_name = DEFAULT_SERVICE_NAME

    def __init__(self):
        self.base_storage_folder = None
        if sys.platform == "win32":
            self.base_storage_folder = pathlib.Path.home() / "AppData" / "Roaming" / self._service_name
            os.makedirs(self.base_storage_folder, exist_ok=True)
        else:
            raise NotImplementedError("We don't yet support platforms other than Windows. Most functionality will translate easily, and if you want Linux support, please reach out")

        self.json_storage = self.base_storage_folder / "auth_data.json"
        self.json_data = self._get_json_storage()

    def _get_json_storage(self) -> dict:
        """
            The application could store credentials for multiple user accounts, so we'll have a simple json file that
            keys usernames to a timestamp we use when hashing the tokens
        """

        if os.path.exists(self.json_storage):
            with open(self.json_storage) as json_data:
                try:
                    return json.load(json_data)
                except json.decoder.JSONDecodeError:  # if we can't decode the JSON, return an empty dictionary
                    return {}
        else:
            return {}

    def _write_json_storage(self) -> None:
        with open(file=self.json_storage, mode='w') as json_output:
            json.dump(self.json_data, json_output)

    def _get_key(self, username) -> bytes:
        crypt_key = self.json_data[username].encode('ascii')
        return crypt_key

    def store(self, username, token):
        """

            This function does two things. First, it makes an entry in the JSON storage with the provided username
            and the timestamp. It will use these to encrypt the token before putting it in the keyring because the
            keyring data is accessible to any application, or at least any Python script. While this strategy provides
            minimal security to a motivated hacker, it at least avoids storing a raw credential anywhere that can be
            retrieved. An attacker would need to either use this library or know its procedure in order to decrypt the
            data in the credential storage.

            Second, it encrypts the password with the information in that entry, then stores that information in the
            credential managger with the keyring package

        Args:
            username (_type_): _description_
            token (_type_): _description_
        """

        crypt_key = cryptography.fernet.Fernet.generate_key()
        # doesn't matter what the previous timestamp was - use the new one now
        self.json_data[username] = crypt_key.decode('utf-8')
        self._write_json_storage()

        # now hash the token and write the actual credential into the keyring
        encrypter = cryptography.fernet.Fernet(crypt_key)
        encrypted_token = encrypter.encrypt(token.encode('ascii')).decode('utf-8')
        keyring.set_password(self._service_name, username, encrypted_token)

    def retrieve_current_token(self, username):
        encrypted_token = keyring.get_password(service_name=self._service_name, username=username).encode('ascii')
        decrypter = cryptography.fernet.Fernet(key=self._get_key(username))
        token = decrypter.decrypt(encrypted_token)
        return token
