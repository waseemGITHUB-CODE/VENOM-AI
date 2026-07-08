"""
VENOM AI — auth/disposable_domains.py
Block disposable / temporary / throwaway email providers at signup.

Why not "Gmail only"?
  Restricting to Gmail blocks all paying business users (Outlook, ProtonMail,
  GSuite custom domains, Yahoo, etc.). The real concern is throwaway mailboxes
  (mailinator, 10minutemail, tempmail, etc.) — so we block those specifically.

The list below covers the ~250 most common disposable providers + their aliases.
"""
from __future__ import annotations

# ── Disposable / throwaway providers ──────────────────────────────────────────
DISPOSABLE_DOMAINS: set[str] = {
    # 10minute / temp-style
    "10minutemail.com", "10minutemail.net", "20minutemail.com", "30minutemail.com",
    "10minutesmail.com", "10minutemail.co.uk", "1secmail.com", "1secmail.net",
    "1secmail.org", "33mail.com", "anonbox.net", "deadaddress.com",

    # Mailinator family
    "mailinator.com", "mailinator.net", "mailinator2.com", "binkmail.com",
    "bobmail.info", "chammy.info", "devnullmail.com", "letthemeatspam.com",
    "mailin8r.com", "mailinator.org", "reallymymail.com", "safetymail.info",
    "sogetthis.com", "spamhereplease.com", "streetwisemail.com", "suremail.info",
    "thisisnotmyrealemail.com", "tradermail.info", "veryrealemail.com",
    "zippymail.info", "notmailinator.com", "spambooger.com", "spamhole.com",

    # Guerrilla mail
    "guerrillamail.com", "guerrillamail.net", "guerrillamail.org", "guerrillamail.biz",
    "guerrillamail.de", "guerrillamailblock.com", "grr.la", "sharklasers.com",
    "spam4.me", "pokemail.net",

    # TempMail family
    "tempmail.com", "tempmail.net", "tempmail.org", "temp-mail.org", "temp-mail.io",
    "temp-mail.ru", "tempinbox.com", "tempinbox.co.uk", "tempemail.com", "tempemail.net",
    "tempemail.co", "tempr.email", "tmpmail.org", "tmpmail.net", "tmpeml.com",
    "tmpbox.net", "tempemails.io", "throwam.com",

    # Yopmail
    "yopmail.com", "yopmail.net", "yopmail.fr", "cool.fr.nf", "jetable.fr.nf",
    "nospam.ze.tc", "nomail.xl.cx", "mega.zik.dj", "speed.1s.fr",

    # Trashmail family
    "trashmail.com", "trashmail.net", "trashmail.org", "trashmail.io", "trashmail.de",
    "trashmail.fr", "trash-mail.com", "trash-mail.de", "trashmailer.com", "trashinbox.com",
    "trashymail.com", "trashemail.de", "wegwerfmail.de", "wegwerfmail.net",
    "wegwerfmail.org", "wegwerpmailadres.nl",

    # Throwaway/disposable specific
    "throwawaymail.com", "throwawayemailaddresses.com", "fakeinbox.com", "fakemail.fr",
    "fakemail.net", "fakemailgenerator.com", "discard.email", "discardmail.com",
    "discardmail.de", "dispostable.com", "emaildrop.io", "emailisvalid.com",
    "emailondeck.com", "emailtemporanea.net", "getairmail.com", "getnada.com",
    "harakirimail.com", "hatespam.org", "incognitomail.com", "jourrapide.com",
    "kasmail.com", "klzlk.com", "kurzepost.de", "lroid.com", "mailcatch.com",
    "maildrop.cc", "mailexpire.com", "mailforspam.com", "mailmoat.com",
    "mailnesia.com", "mailnull.com", "mailtothis.com", "mintemail.com", "mt2009.com",
    "mvrht.net", "no-spam.ws", "nomail.pw", "nospamfor.us", "objectmail.com",
    "obobbo.com", "onewaymail.com", "opayq.com", "pjjkp.com", "plexolan.de",
    "privatemail.com", "punkass.com", "qq.com.net", "rcpt.at", "receiveee.com",
    "rmqkr.net", "rppkn.com", "rtrtr.com", "s0ny.net", "shitmail.me", "shotmail.ru",
    "skeefmail.com", "slopsbox.com", "smellfear.com", "snapmail.cc", "sneakemail.com",
    "soodonims.com", "spam.la", "spam.su", "spamavert.com", "spambob.net",
    "spambog.com", "spambog.de", "spambog.ru", "spambox.us", "spamcero.com",
    "spamday.com", "spamex.com", "spamfree24.org", "spamgourmet.com", "spaminator.de",
    "spamslicer.com", "spamspot.com", "supergreatmail.com", "tafmail.com",
    "tagyourself.com", "tempemail.biz", "tempmail.eu", "tempmaildemo.com",
    "tempmailo.com", "tempymail.com", "thankyou2010.com", "thrma.com",
    "tinymail.fr", "tmail.ws", "tmailinator.com", "tmpjr.me", "toomail.biz",
    "trbvm.com", "trickmail.net", "tyldd.com", "uggsrock.com", "vidchart.com",
    "viditag.com", "vipxm.net", "vsimcard.com", "weg-werf-email.de", "wh4f.org",
    "whatpaas.com", "wronghead.com", "wuzup.net", "wuzupmail.net", "x.ip6.li",
    "xagloo.com", "yapped.net", "yepmail.net", "ymail.org",
    "zoaxe.com", "zoemail.org",

    # mail.tm / similar
    "mail.tm", "mail.com", "inboxbear.com", "minuteinbox.com", "fexbox.org",
    "fexbox.ru", "mohmal.com", "burnermail.io", "dropmail.me", "tempm.ml",

    # Lesser-known but common in attack patterns
    "anonmails.de", "anonymbox.com", "bccto.me", "boun.cr", "bsnow.net",
    "cuvox.de", "dayrep.com", "deagot.com", "dharmatel.net", "dingbone.com",
    "dodgit.com", "doiea.com", "dontreg.com", "drdrb.com", "easytrashmail.com",
    "edgex.ru", "einrot.com", "einrot.de", "estranet.it", "evopo.com",
    "explodemail.com", "fastacura.com", "filzmail.com", "fr33mail.info",
    "fudgerub.com", "fulvie.com", "gehensiemirnichtaufdensack.de",
    "geschent.biz", "get1mail.com", "get2mail.fr", "getairmail.gq", "getmails.eu",
    "gishpuppy.com", "googlemail.org", "gotmail.com", "great-host.in", "greggamel.com",
    "haltospam.com", "hidemail.de", "hidzz.com", "hochsitze.com", "huskion.net",
    "imails.info", "incognitomail.org", "ineec.net", "irish2me.com",
    "jetable.com", "kappala.info", "kismail.ru", "klassmaster.com", "kook.ml",
    "kulturbetrieb.info", "kurzepost.de", "lazyinbox.com", "letthemeatspam.com",
    "lhsdv.com", "loadby.us", "login-email.cf", "login-email.ga", "lookugly.com",
    "mac.hush.com", "mailbiz.biz", "mailblocks.com", "mailbucket.org", "mailde.de",
    "mailde.info", "maileater.com", "mailfa.tk", "mailguard.me", "mailimate.com",
    "mailms.com", "mailnator.com", "mailnesia.com", "mailspeed.ru", "mailtemp.info",
    "mailtempore.com", "mailtome.de", "mailzilla.com", "manifestgenerator.com",
    "mbx.cc", "meantinc.com", "messagebeamer.de", "mierdamail.com", "mintemail.com",
    "moncourrier.fr.nf", "monemail.fr.nf", "monmail.fr.nf", "msa.minsmail.com",
    "msdgs.com", "mt2014.com", "mt2015.com", "muath0n.com", "mybitti.de",
    "mycard.net.ua", "mytrashmail.com",

    # New/recent disposable services
    "nbox.notif.me", "neomailbox.com", "netmails.net", "neverbox.com",
    "nogmailspam.info", "no-spam.ws", "nowmymail.com", "nubescontrol.com",
    "objectmail.com", "obobbo.com", "ourklips.com", "outlawspam.com",
    "ovpn.to", "owlpic.com", "pancakemail.com", "pjjkp.com",
    "politikerclub.de", "pookmail.com", "privatdemail.net", "proxymail.eu",
    "prtnx.com", "putthisinyourspamdatabase.com", "quickinbox.com", "rcpt.at",
    "rebates.stream", "reconmail.com", "regbypass.com", "regbypass.comsafe-mail.net",
    "rejectmail.com", "reklamfri.se", "rhyta.com", "rmqkr.net", "rover.info",
    "rppkn.com", "rtrtr.com", "saynotospams.com", "schafmail.de", "selfdestructingmail.com",
    "selfdestructingmail.org", "sendspamhere.com", "sharedmailbox.org", "sibmail.com",
    "skeefmail.com", "smashmail.de", "smwg.info", "snakemail.com", "sofimail.com",
    "sofort-mail.de", "solvemail.info", "speedgaus.net",
}


def is_disposable_email(email: str) -> bool:
    """Return True if the email's domain is a known disposable provider."""
    if not email or "@" not in email:
        return False
    domain = email.split("@", 1)[1].strip().lower()
    if not domain:
        return False
    # Match exact or subdomain (e.g. foo.mailinator.com matches mailinator.com)
    if domain in DISPOSABLE_DOMAINS:
        return True
    for d in DISPOSABLE_DOMAINS:
        if domain.endswith("." + d):
            return True
    return False
