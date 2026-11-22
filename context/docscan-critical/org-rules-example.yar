/*
  SAMPLE critical-information rules of a made-up organisation (ТОВ «Ромашка-Трейд") - for testing DocScan pass 3
  with docscan-project/test-critical/eval_sensitive.py. NOT shipped: every organisation writes its own rules
  (docscan-project/CRITICAL-RULES.md).

  The text is normalised: lower case, one space between words, no line breaks. Cyrillic: quantifiers count BYTES
  (2 per letter), no Cyrillic inside [...], no \b around Cyrillic words.
  Rule names: ORG_<CATEGORY>_<WHAT>; CATEGORY = BANK PERS CRED KEYS TOK INFRA CLASS ORG.
*/

// ======================================================================== BANK
rule ORG_BANK_CARD
{
    meta:
        description = "Номер платіжної картки поруч зі словом «картка» / card / назвою системи"
        category = "bank"
    strings:
        $c = /(картк|карт(а|и|у|і) |card|visa|mastercard|простір|american express)[^0-9]{0,40}(4[0-9]{3}|5[1-5][0-9]{2}|2(22[1-9]|2[3-9][0-9]|[3-6][0-9]{2}|7[01][0-9]|720)|3[47][0-9]{2}|9804)([0-9]{12}|[0-9]{11}| [0-9]{4} [0-9]{4} [0-9]{3,4}|-[0-9]{4}-[0-9]{4}-[0-9]{3,4}| [0-9]{6} [0-9]{5})([^0-9]|$)/
    condition:
        $c
}

rule ORG_BANK_CARD_TABLE
{
    meta:
        description = "Таблиця з номерами карток (заголовок + 5 і більше номерів)"
        category = "bank"
    strings:
        $h = /(номер картки|номер карти|card number)/
        $n = /(^|[ ,;|])(4[0-9]{3}|5[1-5][0-9]{2}|2(22[1-9]|2[3-9][0-9]|[3-6][0-9]{2}|7[01][0-9]|720)|3[47][0-9]{2}|9804)( [0-9]{4} [0-9]{4} [0-9]{4}|-[0-9]{4}-[0-9]{4}-[0-9]{4}|[0-9]{12})([ ,;|]|$)/
    condition:
        $h and #n >= 5
}

rule ORG_BANK_CARD_MANY
{
    meta:
        description = "5 і більше номерів у форматі картки 4-4-4-4 (з пробілами / дефісами) в одному документі"
        category = "bank"
    strings:
        $n = /(^|[^0-9-])(4[0-9]{3}|5[1-5][0-9]{2}|2(22[1-9]|2[3-9][0-9]|[3-6][0-9]{2}|7[01][0-9]|720)|3[47][0-9]{2}|9804)( [0-9]{4} [0-9]{4} [0-9]{4}|-[0-9]{4}-[0-9]{4}-[0-9]{4})([^0-9-]|$)/
    condition:
        #n >= 5
}

rule ORG_BANK_CVV
{
    meta:
        description = "CVV / CVC / код безпеки картки"
        category = "bank"
    strings:
        $c = /(cvv2?|cvc2?|код безпеки|код на звороті) ?:? ?[0-9]{3,4}([^0-9]|$)/
    condition:
        $c
}

rule ORG_BANK_IBAN_UA
{
    meta:
        description = "IBAN України (UA + 27 цифр)"
        category = "bank"
    strings:
        $i = /(^|[^a-z])ua ?[0-9]{2}( ?[0-9]){25}([^0-9]|$)/
    condition:
        $i
}

rule ORG_BANK_SWIFT
{
    meta:
        description = "SWIFT/BIC банку України в реквізитах"
        category = "bank"
    strings:
        $s = /swift(\/bic)? ?:? ?[a-z]{4}ua[a-z0-9]{2}/
    condition:
        $s
}

rule ORG_BANK_PIN
{
    meta:
        description = "ПІН-код картки"
        category = "bank"
    strings:
        $p = /(^| )(пін|pin)(-код| код)? ?:? ?[0-9]{4}( |$|[.,;])/
    condition:
        $p
}

rule ORG_BANK_ONLINE_CREDS
{
    meta:
        description = "Логін / пароль до клієнт-банку чи інтернет-банкінгу"
        category = "bank"
    strings:
        $b = /(клієнт-банк|client-bank|приват24|монобанк|monobank).{0,160}пароль/
    condition:
        $b
}

// ======================================================================== PERSONAL
rule ORG_PERS_RNOKPP
{
    meta:
        description = "РНОКПП (ІПН) з контекстом"
        category = "personal"
    strings:
        $r = /(рнокпп|іпн|ідентифікаційн[^ ]{0,8} (код|номер)|податков[^ ]{0,8} номер)[^0-9]{0,30}[0-9]{10}([^0-9]|$)/
    condition:
        $r
}

rule ORG_PERS_RNOKPP_LIST
{
    meta:
        description = "Список / таблиця з РНОКПП (заголовок + 10 і більше номерів)"
        category = "personal"
    strings:
        $h = /(рнокпп|іпн)/
        $n = /(^| )[0-9]{10}( |$)/
    condition:
        $h and #n >= 10
}

rule ORG_PERS_PASSPORT
{
    meta:
        description = "Паспорт (серія + номер) поруч зі словом «паспорт»"
        category = "personal"
    strings:
        $p = /паспорт[^0-9]{0,24}сері[^0-9]{0,24}[0-9]{6}([^0-9]|$)/
    condition:
        $p
}

rule ORG_PERS_ID_UNZR
{
    meta:
        description = "ID-картка або запис ЄДДР / УНЗР"
        category = "personal"
    strings:
        $u = /(^|[^0-9])(19|20)[0-9]{6}-[0-9]{5}([^0-9]|$)/
        $i = /(id-картк|ід-картк|id картк)[^0-9]{0,30}[0-9]{9}([^0-9]|$)/
    condition:
        any of them
}

rule ORG_PERS_FOREIGN_DRIVER
{
    meta:
        description = "Закордонний паспорт / посвідчення водія"
        category = "personal"
    strings:
        $f = /закордонн[^ ]{0,8} паспорт[^ ]{0,4} ?[a-z]{2}[0-9]{6}/
        $d = /посвідчення водія[^0-9]{0,16}[0-9]{6}/
    condition:
        any of them
}

rule ORG_PERS_DOB_ADDRESS
{
    meta:
        description = "Дата народження разом з адресою (персональні дані без номерів документів)"
        category = "personal"
    strings:
        $d = /(дата народження|д\.н\.) ?:? ?[0-9]{2,4}[.\-\/][0-9]{2}[.\-\/][0-9]{2,4}/
        $a = /(^| )адреса/
    condition:
        $d and $a
}

rule ORG_PERS_PHONES_BULK
{
    meta:
        description = "Багато мобільних номерів в одному документі (база контактів)"
        category = "personal"
    strings:
        $p = /\+380 ?\(?[0-9]{2}\)? ?[0-9]{3}[ -]?[0-9]{2}[ -]?[0-9]{2}/
    condition:
        #p >= 10
}

// ======================================================================== CREDENTIALS
rule ORG_CRED_PASSWORD
{
    meta:
        description = "Пароль, записаний явно (пароль: … / password=…)"
        category = "credentials"
    strings:
        $eq = /(пароль|password|passwd|pwd)=[^ <\[;_*][^ <\[;]{5,}/
        $co = /(пароль|password|passwd|pwd)( від wi-fi| до ключа)? ?(:|—| - ) ?[^ <\[;_*][^ <\[;]{5,}/
        $sp = /(^| )(пароль|password) [a-z0-9!#$%&@._-]{2,}[0-9][a-z0-9!#$%&*@._-]{1,}( |$|[.,;])/
        $mid = /(пароль|password)[^:=.]{1,60}(:|—) ?[a-z0-9!#$%&@._+-]{6,}/
        $rdp = "password 51:b:"
    condition:
        any of them
}

rule ORG_CRED_URL
{
    meta:
        description = "Адреса з логіном і паролем (схема://користувач:пароль@хост)"
        category = "credentials"
    strings:
        $u = /[a-z]{2,10}:\/\/[^\/ :@]{1,40}:[^@ \/]{4,60}@[a-z0-9.-]{3,}/
    condition:
        $u
}

rule ORG_CRED_TABLE
{
    meta:
        description = "Таблиця облікових записів: заголовок логін/пароль і значення, схожі на паролі"
        category = "credentials"
    strings:
        $h = /(логін|login|username|user)[ ,;|](пароль|password)/
        $pw = /(^|[ ,;|])[a-z0-9]{3,}[!#$%&*@][a-z0-9]{3,}([ ,;|]|$)/
    condition:
        $h and #pw >= 2
}

rule ORG_CRED_HASH
{
    meta:
        description = "Хеші паролів (bcrypt; NTLM / MD5 у вивантаженні з password_hash)"
        category = "credentials"
    strings:
        $b = /\$2[aby]\$[0-9]{2}\$[.\/a-z0-9]{53}/
        $ctx = /(password_hash|ntlm|nthash)/
        $h = /(^| )[0-9a-f]{32}( |$)/
    condition:
        $b or ($ctx and #h >= 3)
}

// ======================================================================== KEYS
rule ORG_KEYS_PEM_PRIVATE
{
    meta:
        description = "Приватний ключ PEM / OpenSSH / PGP"
        category = "keys"
    strings:
        $k = /-----begin ([a-z]{2,10} )?private key----- ?[a-z0-9+\/]{40}/
        $g = "-----begin pgp private key block-----"
    condition:
        any of them
}

rule ORG_KEYS_PUTTY
{
    meta:
        description = "Ключ PuTTY"
        category = "keys"
    strings:
        $a = "putty-user-key-file-"
        $b = "private-lines:"
    condition:
        all of them
}

rule ORG_KEYS_KEP
{
    meta:
        description = "Ключ КЕП / ЕЦП разом з паролем до нього"
        category = "keys"
    strings:
        $kp = /(key-[a-z0-9]{1,10}\.dat|(^| )кеп( |$|[.,;:)])|(^| )ецп( |$|[.,;:)])).{0,200}пароль[^.:]{0,80}(:|—) ?[^ <\[;_*.][^ <\[;]{3,}/
    condition:
        $kp
}

rule ORG_KEYS_SEED
{
    meta:
        description = "Сід-фраза криптогаманця (12+ слів)"
        category = "keys"
    strings:
        $s = /(seed phrase|recovery phrase|мнемонічн[^ ]{0,8} фраз)[^a-z]{0,80}([a-z]{3,8} ){11}[a-z]{3,8}/
    condition:
        $s
}

// ======================================================================== TOKENS
rule ORG_TOK_API
{
    meta:
        description = "Токен / ключ API хмарного сервісу (AWS, Google, GitHub, GitLab, Slack, Telegram, Azure, Stripe, OpenAI, JWT, Bearer)"
        category = "tokens"
    strings:
        $aws = /(^|[^a-z0-9])akia[0-9a-z]{16}([^a-z0-9]|$)/
        $aws_s = /aws_secret_access_key ?[=:] ?[0-9a-z\/+]{40}/
        $google = /aiza[0-9a-z_\-]{35}/
        $gh = /(^|[^a-z0-9])ghp_[0-9a-z]{36}/
        $ghpat = /github_pat_[0-9a-z_]{82}/
        $gl = /glpat-[0-9a-z_\-]{20}/
        $slack = /xox[baprs]-[0-9]{6,}-[0-9a-z-]{10,}/
        $hook = "hooks.slack.com/services/t"
        $tg = /(^|[^0-9])[0-9]{8,10}:aa[0-9a-z_\-]{33}/
        $azure = /accountkey=[a-z0-9\/+]{40,}/
        $stripe = /sk_live_[0-9a-z]{20,}/
        $openai = /sk-(proj-|ant-)?[0-9a-z_\-]{40,}/
        $jwt = /eyj[0-9a-z_\-]{10,}\.eyj[0-9a-z_\-]{10,}\.[0-9a-z_\-]{20,}/
        $bearer = /bearer [0-9a-z_\-.]{30,}/
        // documentation placeholders
        $ex1 = "example"
        $ex2 = "your_api_key"
        $ex3 = "xxxxxxxx"
    condition:
        any of ($aws, $aws_s, $google, $gh, $ghpat, $gl, $slack, $hook, $tg, $azure, $stripe, $openai, $jwt, $bearer) and not any of ($ex*)
}

// ======================================================================== INFRA
rule ORG_INFRA_CONFIG
{
    meta:
        description = "Конфігурація з секретами: VPN (OpenVPN / WireGuard), kubeconfig, .env, дамп users"
        category = "infra"
    strings:
        $ovpn = /<key> ?-----begin/
        $wg = /privatekey ?= ?[a-z0-9+\/]{40}/
        $kube = /client-key-data: ?[a-z0-9+\/]{40}/
        $env = /(db_password|secret_key|api_token)=[^ ]{4,}/
        $sql = /insert into [a-z_]{0,20}users? ?\(/
        $sqlpw = /password/
    condition:
        $ovpn or $wg or $kube or $env or ($sql and $sqlpw)
}

// ======================================================================== CLASSIFIED
rule ORG_CLASS_GRIF
{
    meta:
        description = "Гриф обмеженого доступу"
        category = "classified"
    strings:
        $dsk = /(^| )(д|d)(с|c)(к|k)( |$|[.,;:!?)])/
        $dsk2 = /для службов[^ ]{0,8} користуванн[^ ]{0,8}/
        $t = /(^| )(цілком )?таємно( |$|[.,;:!?)])/
        $kt = /комерційн[^ ]{0,8} таємниц/
        $conf = /(^| )конфіденційно( |$|[.,;:!?)])/
        $en1 = /(^| )confidential( |$|[.,;:!?)])/
        $en2 = "internal use only"
        $en3 = "strictly confidential"
        $nd = "не підлягає розголошенню"
    condition:
        any of ($dsk, $dsk2, $t, $kt, $conf, $en2, $en3, $nd) or $en1 in (0..200)
}

// ======================================================================== ORGANISATION (made-up org)
rule ORG_ORG_TERMS
{
    meta:
        description = "Внутрішні терміни ТОВ «Ромашка-Трейд»: проєкти, договори, домен і сервери"
        category = "org"
    strings:
        $p1 = "проєкт «сокіл»"
        $p2 = "project falcon"
        $p3 = "операція грім"
        $contract = /№ ?рт-[0-9]{4}\/[0-9]{2}/
        $dom = "romashka.local"
        $srv = "srv-buh-01"
    condition:
        any of them
}
