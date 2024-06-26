from dataclasses import dataclass


@dataclass
class VendorEntity:
    vendor_id: str
    vendor_name: str


@dataclass
class MicrosoftEntity(VendorEntity):
    userPrincipalName: str
    id: str
    displayName: str
    surname: str
    givenName: str
    preferredLanguage: str
    mail: str
    mobilePhone: str
    jobTitle: str
    officeLocation: str
    businessPhones: list


@dataclass
class GoogleEntity(VendorEntity):
    id: str
    email: str
    verified_email: bool
    picture: str


    