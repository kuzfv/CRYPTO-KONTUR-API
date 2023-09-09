import os
import time
import uuid
import base64
import hashlib
import requests
import subprocess


GOST = False  # Set True if GOST-TLS using


### External staging
# CERT = os.getenv("ES-CLOUD-CERTIFICATE")
# URL = "http://cloudtest.kontur-ca.ru/v3"

### Internal staging
CERT = os.getenv("IS-CLOUD-CERTIFICATE")
URL = os.getenv("IS-CLOUD-URL")


# Settings for GOST TLS tunnel connection
if GOST:
    URL = "http://localhost:8300"
    CERT = None


def base64_encoder(filepath: str) -> str:
    """Returns Base64 content of file"""

    with open(filepath, "rb") as file:
        return base64.b64encode(file.read()).decode()


def get_thumbprint(certificate: str) -> str:
        """Calculate thumbprint of certificate"""

        data = hashlib.sha1()
        with open(certificate, "rb") as file:
            chunk = file.read(8192)
            while chunk:
                data.update(chunk)
                chunk = file.read(8192)
        return data.hexdigest()


def get_gost_hash(file: str) -> str:
    """Calculate GOST R 34.11-2012 hash of file"""

    hashfile = subprocess.check_output(f"./cpverify.exe -mk -alg GR3411_2012_256 {file}",
                                       stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    return hashfile.decode().strip()


def strip_filename(filepath: str) -> str:
    """Returns filename only excluding path"""

    return ".".join(filepath.split("/")[-1].split(".")[:-1])


def create_file(filepath: str) -> dict:
    """Create file in the Cloudcrypt"""

    def get_length() -> int:
        """Calculate length of file"""
        
        nonlocal filepath
        length = os.path.getsize(filepath)
        return length
    
    def get_hash() -> str:
        """Calculate MD5 hash of file"""

        nonlocal filepath
        data = hashlib.md5()
        with open(filepath, "rb") as file:
            chunk = file.read(8192)
            while chunk:
                data.update(chunk)
                chunk = file.read(8192)
        return data.hexdigest()
    
    req = requests.post(URL + "/CreateFile", params={"certificate": CERT,
                                                     "md5": get_hash(),
                                                     "length": get_length(),
                                                     "fileName": strip_filename(filepath)})
    if req.status_code == 200:
        return req.json()
    else:
        raise requests.HTTPError(req.text)


def upload_chunk(filepath: str, file_id: str, offset: int = 0) -> None:
    """Upload chunks of file"""

    assert isinstance(offset, int), "'offset' parameter must be integer type"
    
    max_block_size = 16777216  # 16 Megabytes
    with open(filepath, "rb") as file:
        n = 1
        chunk = file.read(max_block_size)
        while chunk:
            with requests.post(URL + "/UploadChunk",
                               headers={'Content-Type': 'application/pdf'},
                               params={"certificate": CERT, "fileId": file_id, "offset": offset},
                               data=chunk) as req:
                chunk = file.read(max_block_size)
                offset += max_block_size
                n += 1


def reg_cryptooperation_with_files(file_ids: list, certpath: str, cert_type: str = "thumbprint",
                                   confirm_message_template: int = 0, disable_certificate_confirm: bool = False,
                                   disable_server_sign: bool = True, sign_type: int = 0) -> dict:
    """Registration cryptooperation with upload file on the Cloudcrypt"""

    assert cert_type in ("thumbprint", "base64"), "'cert_type' parameter must be 'thumbprint' or 'base64' only"
    assert 0 <= confirm_message_template <= 4, "'confirm_message_template' parameter must be from 1 to 4 only"
    assert isinstance(disable_certificate_confirm, bool), "'disable_certificate_confirm' parameter must be boolean type"
    assert isinstance(disable_server_sign, bool), "'disable_server_sign' parameter must be boolean type"
    assert 0 <= sign_type <= 3, "'sign_type' parameter must be from 1 to 3 only" 
    
    payload = {"Thumbprint": get_thumbprint(certpath) if cert_type == "thumbprint" else None,
               "CertificateBase64": base64_encoder(certpath) if cert_type == "base64" else None,
               "FileIds": file_ids,
               "ConfirmMessage": {
                   "Template": confirm_message_template
                   },
               "DisableCertificateConfirm": disable_certificate_confirm,
               "DisableServerSign": disable_server_sign,
               "SignType": sign_type
               }
    req = requests.post(URL + "/Sign", params={"certificate": CERT}, json=payload)
    if req.status_code == 200:
        return req.json()
    else:
        raise requests.HTTPError(req.text)


def reg_cryptooperation_without_files(filepaths: list, certpath: str, content_type: str = "serialized",
                                      cert_type: str = "thumbprint", confirm_message_template: int = 0,
                                      disable_certificate_confirm: bool = False, disable_server_sign: bool = True,
                                      sign_type: int = 0) -> dict:
    """Registration cryptooperation withouth upload file on the Cloudcrypt"""

    assert cert_type in ("thumbprint", "base64"), "'cert_type' parameter must be 'thumbprint' or 'base64' only"
    assert content_type in ("serialized", "hashes"), "'content_type' parameter must be 'serialized' or 'hashes' only"
    assert 0 <= confirm_message_template <= 4, "'confirm_message_template' parameter must be from 1 to 4 only"
    assert isinstance(disable_certificate_confirm, bool), "'disable_certificate_confirm' parameter must be boolean type"
    assert isinstance(disable_server_sign, bool), "'disable_server_sign' parameter must be boolean type"
    assert 0 <= sign_type <= 3, "'sign_type' parameter must be from 1 to 3 only" 
    
    payload = {"Thumbprint": get_thumbprint(certpath) if cert_type == "thumbprint" else None,
               "CertificateBase64": base64_encoder(certpath) if cert_type == "base64" else None,
               "SerializedFiles": [{
                   "Id": str(uuid.uuid4()),
                   "FileName": strip_filename(file),
                   "ContentBase64": base64_encoder(file)
                   }
                                   for file in filepaths] if content_type == "serialized" else None,
               "FileHashes": [{
                   "FileName": strip_filename(file),
                   "HashContent": get_gost_hash(file)
                   }
                              for file in filepaths] if content_type == "hashes" else None,
               "ConfirmMessage": {
                   "Template": confirm_message_template
                   },
               "DisableCertificateConfirm": disable_certificate_confirm,
               "DisableServerSign": disable_server_sign,
               "SignType": sign_type
               }
    
    req = requests.post(URL + "/Sign", params={"certificate": CERT}, json=payload)
    if req.status_code == 200:
        return req.json()
    else:
        raise requests.HTTPError(req.text)


def confirm_operation(operation_id: str, confirmation_code: int):
    """Start confirm cryptooperation"""

    req = requests.post(URL + "/Confirm", params={"certificate": CERT,
                                                  "operationId": operation_id,
                                                  "confirmationCode": confirmation_code})
    if req.status_code == 200:
        return req.json()
    else:
        raise requests.HTTPError(req.text)


def get_status(operation_id: str):
    """Get status of cryptooperation"""

    req = requests.get(URL + "/GetStatus", params={"certificate": CERT, "operationId": operation_id})
    if req.status_code == 200:
        return req.json()
    else:
        raise requests.HTTPError(req.text)


def get_result(result_id: str, size: int, offset: int = 0) -> bytes | dict:
    """Get signature content"""

    assert isinstance(size, int), "'size' variable must be integer type"
    assert isinstance(offset, int), "'offset' variable must be integer type"
    
    req = requests.get(URL + "/GetResult", params={"certificate": CERT,
                                                    "resultId": result_id,
                                                    "size": size,
                                                    "offset": offset})
    if req.status_code == 200:
        return req.content
    else:
        raise requests.HTTPError(req.text)


def main(filepaths: list, certpath: str, upload_files: bool = False, content_type="hashes",
         cert_type: str = "thumbprint", confirm_message_template: int = 0,
         disable_certificate_confirm: bool = False, disable_server_sign: bool = True,
         sign_type: int = 0) -> bytes:
    """Select file, certificate and get the signature"""

    assert isinstance(upload_files, bool), "'upload_files' variable must be boolean type"

    file_ids = []
    if upload_files:
        for file in filepaths:
            fileinfo = create_file(file)
            file_id = fileinfo.get("FileId")
            length = fileinfo.get("Length")
            upload = upload_chunk(file, file_id, length)
            file_ids.append(file_id)
        operation = reg_cryptooperation_with_files(file_ids, certpath, cert_type=cert_type,
                                                   confirm_message_template=confirm_message_template,
                                                   disable_certificate_confirm=disable_certificate_confirm,
                                                   disable_server_sign=disable_server_sign,
                                                   sign_type=sign_type)
    else:
        operation = reg_cryptooperation_without_files(filepaths, certpath, cert_type=cert_type,
                                                      content_type=content_type,
                                                      confirm_message_template=confirm_message_template,
                                                      disable_certificate_confirm=disable_certificate_confirm,
                                                      disable_server_sign=disable_server_sign,
                                                      sign_type=sign_type)
    if operation.get("ConfirmType") == 1:
        sms = input("Please imput SMS code to confirm: ")
        confirm = confirm_operation(operation.get("OperationId"), int(sms))
    elif operation.get("ConfirmType") == 2:
        input("Please approve PUSH notification in myDSS app to confirm and press Enter")
    elif operation.get("ConfirmType") == 4:
        input("Please approve PUSH notification in Kontur mobile app to confirm and press Enter")
    while True:
        status = get_status(operation.get("OperationId"))
        if status.get("OperationStatus") > 1:
            break
        else:
            time.sleep(1)
    if status.get("OperationStatus") != 2:
        return b''
    else:
        for i, res in enumerate(status.get("FileStatuses")):
            result = get_result(res.get("ResultId"), res.get("ResultSize"))
            with open(f"{filepaths[i]}.sig", "wb") as signature:
                signature.write(result)


if __name__ == "__main__":
    ...
