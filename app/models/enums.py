import enum


class Role(enum.StrEnum):
    citizen = "citizen"
    moderator = "moderator"
    admin = "admin"


class EntityType(enum.StrEnum):
    phone = "phone"
    upi = "upi"
    url = "url"


class ScamType(enum.StrEnum):
    kyc_update = "kyc_update"
    fake_job = "fake_job"
    lottery_prize = "lottery_prize"
    upi_collect = "upi_collect"
    loan_app = "loan_app"
    impersonation = "impersonation"
    investment = "investment"
    delivery = "delivery"
    other = "other"


class ReportStatus(enum.StrEnum):
    pending = "pending"
    verified = "verified"
    rejected = "rejected"


class Verdict(enum.StrEnum):
    likely_safe = "likely_safe"
    suspicious = "suspicious"
    high_risk = "high_risk"


class IndianState(enum.StrEnum):
    """28 states + 8 union territories. Used on sign-up so reports can be routed to the right state cyber cell."""
    andaman_and_nicobar = "Andaman and Nicobar Islands"
    andhra_pradesh = "Andhra Pradesh"
    arunachal_pradesh = "Arunachal Pradesh"
    assam = "Assam"
    bihar = "Bihar"
    chandigarh = "Chandigarh"
    chhattisgarh = "Chhattisgarh"
    dadra_nagar_haveli_daman_diu = "Dadra and Nagar Haveli and Daman and Diu"
    delhi = "Delhi"
    goa = "Goa"
    gujarat = "Gujarat"
    haryana = "Haryana"
    himachal_pradesh = "Himachal Pradesh"
    jammu_and_kashmir = "Jammu and Kashmir"
    jharkhand = "Jharkhand"
    karnataka = "Karnataka"
    kerala = "Kerala"
    ladakh = "Ladakh"
    lakshadweep = "Lakshadweep"
    madhya_pradesh = "Madhya Pradesh"
    maharashtra = "Maharashtra"
    manipur = "Manipur"
    meghalaya = "Meghalaya"
    mizoram = "Mizoram"
    nagaland = "Nagaland"
    odisha = "Odisha"
    puducherry = "Puducherry"
    punjab = "Punjab"
    rajasthan = "Rajasthan"
    sikkim = "Sikkim"
    tamil_nadu = "Tamil Nadu"
    telangana = "Telangana"
    tripura = "Tripura"
    uttar_pradesh = "Uttar Pradesh"
    uttarakhand = "Uttarakhand"
    west_bengal = "West Bengal"
