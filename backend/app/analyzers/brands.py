"""
Brands that phishing emails commonly impersonate, with the domains
each brand really sends email from. Includes Israeli brands, since
local phishing (banks, Israel Post) often targets Hebrew-speaking users.

Each entry: brand id -> (names as they may appear, official base domains).
The first name is the one shown to the user; matching ignores case.
"""
BRANDS: dict[str, tuple[list[str], set[str]]] = {
    "paypal": (["PayPal"], {"paypal.com"}),
    "apple": (["Apple", "iCloud"], {"apple.com", "icloud.com"}),
    "microsoft": (
        ["Microsoft", "Outlook", "Office 365", "Office365"],
        {"microsoft.com", "microsoftonline.com", "office.com", "outlook.com", "live.com"},
    ),
    "google": (["Google", "Gmail"], {"google.com", "youtube.com"}),
    "amazon": (["Amazon"], {"amazon.com", "amazon.co.uk", "amazonaws.com"}),
    "netflix": (["Netflix"], {"netflix.com"}),
    "facebook": (["Facebook", "Meta"], {"facebook.com", "facebookmail.com", "meta.com"}),
    "instagram": (["Instagram"], {"instagram.com", "facebookmail.com"}),
    "linkedin": (["LinkedIn"], {"linkedin.com"}),
    "dhl": (["DHL"], {"dhl.com", "dhl.co.il"}),
    "israel_post": (["Israel Post", "דואר ישראל"], {"israelpost.co.il"}),
    "bank_hapoalim": (["Bank Hapoalim", "Hapoalim", "הפועלים"], {"bankhapoalim.co.il"}),
    "bank_leumi": (["Bank Leumi", "Leumi", "לאומי"], {"leumi.co.il", "bankleumi.co.il"}),
}
