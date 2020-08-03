unit OpenSSL.Api_11;
{ Cross-platform unified OpenSSL 1.1.1 stub library unit for OpenSSL }

interface

uses
  {$IFDEF MSWINDOWS}
  Winapi.Windows,
  {$ENDIF}
  {$IFDEF POSIX}
  Posix.SysTypes,
  {$ENDIF}
  System.Types,
  System.SysUtils,
  System.SyncObjs;

const
  {$IF Defined(WIN32)}
  LIB_CRYPTO = 'libcrypto-1_1.dll';
  LIB_SSL = 'libssl-1_1.dll';
  PREFIX = '';
  {$ELSEIF Defined(WIN64)}
  LIB_CRYPTO = 'libcrypto-1_1-x64.dll';
  LIB_SSL = 'libssl-1_1-x64.dll';
  PREFIX = '';
  {$ELSEIF Defined(ANDROID64)}
  LIB_CRYPTO = 'libcrypto-android64.a';
  LIB_SSL = 'libssl-android64.a';
  PREFIX = '';
  {$ELSEIF Defined(ANDROID32)}
  LIB_CRYPTO = 'libcrypto-android32.a';
  LIB_SSL = 'libssl-android32.a';
  PREFIX = '';
  {$ELSEIF Defined(IOS)}
  LIB_CRYPTO = 'libcrypto-ios.a';
  LIB_SSL = 'libssl-ios.a';
  PREFIX = '';
  {$ELSEIF Defined(MACOS32)}
  LIB_CRYPTO = 'libssl-merged-osx32.dylib'; { We unify LibSsl and LibCrypto into a common shared library on macOS }
  LIB_SSL = 'libssl-merged-osx32.dylib';
  PREFIX = '_';
  {$ELSEIF Defined(MACOS64)}
  LIB_CRYPTO = 'libcrypto-osx64.a';
  LIB_SSL = 'libssl-osx64.a';
  PREFIX = '';
  {$ELSEIF Defined(LINUX)}
  LIB_CRYPTO = 'libcrypto.so';
  LIB_SSL = 'libssl.so';
  PREFIX = '';
  {$ELSE}
    {$MESSAGE Error 'Unsupported platform'}
  {$ENDIF}

{ LibCrypto types }
type
  ASN_STRING = record
    length : LongInt;
    _type : LongInt;
    data : PAnsiChar;
    flags : LongInt;
  end;

  { Opaque types }
  BN_ULONG = Cardinal;
  PASN1_STRING = ^ASN_STRING;
  PASN1_OCTET_STRING = Pointer;
  PASN1_BIT_STRING = Pointer;
  PASN1_TIME = Pointer;
  PASN1_INTEGER = Pointer;
  PBIO = Pointer;
  PBIO_METHOD = Pointer;
  PX509_NAME = Pointer;
  PBN_GENCB = Pointer;
  PBN_ULONG = ^BN_ULONG;
  PSTACK = Pointer;
  PEVP_MD = Pointer;
  PEVP_MD_CTX = Pointer;
  PEngine = Pointer;
  PEVP_PKEY_CTX = Pointer;
  PEVP_PKEY = Pointer;
  PPEVP_PKEY = ^PEVP_PKEY;
  PRSA = Pointer;
  PPRSA = ^PRSA;
  PASN1_OBJECT = Pointer;
  PASN1_TYPE = Pointer;
  PLHASH = Pointer;
  PX509V3_CTX = Pointer;

  TBIGNUM = packed record
    d: PBN_ULONG;
    top: Integer;
    dmax: Integer;
    neg: Integer;
    flags: Integer;
  end;
  PBIGNUM = ^TBIGNUM;

  TX509_ALGOR = record
    algorithm: PASN1_OBJECT;
    parameter: PASN1_TYPE;
  end;
  PX509_ALGOR = ^TX509_ALGOR;

  TX509_CRL_INFO = record
    version: PASN1_INTEGER;
    sig_alg: PX509_ALGOR;
    issuer: PX509_NAME;
    lastUpdate: PASN1_TIME;
    nextUpdate: PASN1_TIME;
  end;
  PX509_CRL_INFO = ^TX509_CRL_INFO;

  TX509_CRL = record
    crl: PX509_CRL_INFO;
    sig_alg: PX509_ALGOR;
    signature: PASN1_BIT_STRING;
    references: Integer;
  end;
  PX509_CRL = ^TX509_CRL;
  PPX509_CRL = ^PX509_CRL;

  TX509_VAL = record
    notBefore: PASN1_TIME;
    notAfter: PASN1_TIME;
  end;
  PX509_VAL = ^TX509_VAL;

  TX509_PUBKEY = record
    algor: PX509_ALGOR;
    public_key: PASN1_BIT_STRING;
    pkey: PEVP_PKEY;
  end;
  PX509_PUBKEY = ^TX509_PUBKEY;

  { Certificate info }
  TX509_CINF = record
    version: PASN1_INTEGER;
    serialNumber: PASN1_INTEGER;
    signature: PX509_ALGOR;
    issuer: PX509_NAME;
    validity: PX509_VAL;
    subject: PX509_NAME;
    key: PX509_PUBKEY;
  end;
  PX509_CINF = ^TX509_CINF;

  TX509 = record
    cert_info: PX509_CINF;
    sig_alg: PX509_ALGOR;
    signature: PASN1_BIT_STRING;
    valid: Integer;
    references: Integer;
    name: MarshaledAString;
  end;
  PX509 = ^TX509;
  PPX509 = ^PX509;

  TASN1_ENCODING = packed record
    enc: Pointer;
    len: LongWord;
    modified: Integer;
  end;
  PASN1_ENCODING = ^TASN1_ENCODING;

  TX509_REQ_INFO = packed record
    enc: TASN1_ENCODING;
    version: PASN1_INTEGER;
    subject: PX509_NAME;
    pubkey: PX509_PUBKEY;
    attributes: PSTACK;
  end;
  PX509_REQ_INFO = ^TX509_REQ_INFO;

  TX509_REQ = packed record
    req_info: PX509_REQ_INFO;
    sig_alg: PX509_ALGOR;
    signature: PASN1_STRING;
    references: Integer;
  end;
  PX509_REQ = ^TX509_REQ;
  PPX509_REQ = ^PX509_REQ;

  ASN1_BOOLEAN = Longint;
  TX509_EXTENSION = record
    object_: PASN1_OBJECT;
    critical: ASN1_BOOLEAN;
    value: PASN1_OCTET_STRING;
  end;
  PX509_EXTENSION = ^TX509_EXTENSION;

  TPEM_Password_Callback = function(ABuffer: Pointer; ANum: Integer; ARWFlag: Integer; AUserData: Pointer): Integer; cdecl;

const
  { Objects }
  NID_rsaEncryption = 6;
  NID_subject_alt_name = 85;

  { ASN1 }
  MBSTRING_FLAG = $1000;
  MBSTRING_ASC = MBSTRING_FLAG or 1;
  RSA_F4 = $10001;
  EVP_PKEY_RSA = NID_rsaEncryption;

{ LibCrypto exports }
function ASN1_INTEGER_new: PASN1_INTEGER; cdecl external LIB_CRYPTO name PREFIX + 'ASN1_INTEGER_new'
  {$IF Defined(ANDROID64)}
  dependency 'crypto-android64' dependency 'ssl-android64'
  {$ELSEIF Defined(ANDROID32)}
  dependency 'crypto-android32' dependency 'ssl-android32'
  {$ENDIF};
procedure ASN1_INTEGER_free(AASN1: PASN1_INTEGER); cdecl external LIB_CRYPTO name PREFIX + 'ASN1_INTEGER_free';

function BN_bin2bn(ABin: Pointer; ALen: integer; ARet: PBIGNUM): PBIGNUM; cdecl external LIB_CRYPTO name PREFIX + 'BN_bin2bn';
procedure BN_free(ABN: PBIGNUM); cdecl external LIB_CRYPTO name PREFIX + 'BN_free';
function BN_new: PBIGNUM; cdecl external LIB_CRYPTO name PREFIX + 'BN_new';
function BN_set_word(ABN: PBIGNUM; W: BN_ULONG): Integer; cdecl external LIB_CRYPTO name PREFIX + 'BN_set_word';
function BN_to_ASN1_INTEGER(const ABN: PBIGNUM; AASN1: PASN1_INTEGER): PASN1_INTEGER; cdecl external LIB_CRYPTO name PREFIX + 'BN_to_ASN1_INTEGER';

function BIO_ctrl_pending(ABIO: PBIO): SIZE_T; cdecl external LIB_CRYPTO name PREFIX + 'BIO_ctrl_pending';
function BIO_free(ABIO: PBIO): Integer; cdecl external LIB_CRYPTO name PREFIX + 'BIO_free';
function BIO_new(ABIO_METHOD: PBIO_METHOD): PBIO; cdecl external LIB_CRYPTO name PREFIX + 'BIO_new';
function BIO_new_mem_buf(ABuffer: Pointer; ALen: Integer): PBIO; cdecl external LIB_CRYPTO name PREFIX + 'BIO_new_mem_buf';
function BIO_read(ABIO: PBIO; ABuffer: Pointer; ALen: Integer): Integer; cdecl external LIB_CRYPTO name PREFIX + 'BIO_read';
function BIO_s_mem: PBIO_METHOD; cdecl external LIB_CRYPTO name PREFIX + 'BIO_s_mem';
function BIO_write(ABIO: PBIO; ABuffer: Pointer; ALen: Integer): Integer; cdecl external LIB_CRYPTO name PREFIX + 'BIO_write';

function EVP_Digest(AData: Pointer; ACount: Integer; AMD: Pointer; var ASize: Integer; AEVP_MD: PEVP_MD; AEngine: PEngine): Integer; cdecl external LIB_CRYPTO name PREFIX + 'EVP_Digest';
function EVP_DigestFinal_ex(AEVP_MD_CTX: PEVP_MD_CTX; md: Pointer; var s: Integer): Integer; cdecl external LIB_CRYPTO name PREFIX + 'EVP_DigestFinal_ex';
function EVP_DigestInit_ex(AEVP_MD_CTX: PEVP_MD_CTX; etype: PEVP_MD; impl: PEngine): Integer; cdecl external LIB_CRYPTO name PREFIX + 'EVP_DigestInit_ex';
function EVP_DigestUpdate(AEVP_MD_CTX: PEVP_MD_CTX; d: Pointer; cnt: Integer): Integer; cdecl external LIB_CRYPTO name PREFIX + 'EVP_DigestUpdate';
function EVP_DigestFinal(AEVP_MD_CTX: PEVP_MD_CTX; md: Pointer; var s: Integer): Integer; cdecl external LIB_CRYPTO name PREFIX + 'EVP_DigestFinal';
function EVP_DigestInit(AEVP_MD_CTX: PEVP_MD_CTX; etype: PEVP_MD): Integer; cdecl external LIB_CRYPTO name PREFIX + 'EVP_DigestInit';
function EVP_DigestSign(AEVP_MD_CTX: PEVP_MD_CTX; sigret: Pointer; var siglen: Integer; tbsret: Pointer; tbslen: Integer): Integer; cdecl external LIB_CRYPTO name PREFIX + 'EVP_DigestSign';
function EVP_DigestSignInit(AEVP_MD_CTX: PEVP_MD_CTX; AEVP_PKEY_CTX: PEVP_PKEY_CTX; etype: PEVP_MD; impl: PEngine; AKey: PEVP_PKEY): Integer; cdecl external LIB_CRYPTO name PREFIX + 'EVP_DigestSignInit';
function EVP_DigestSignFinal(AEVP_MD_CTX: PEVP_MD_CTX; sigret: Pointer; var siglen: Integer): Integer; cdecl external LIB_CRYPTO name PREFIX + 'EVP_DigestSignFinal';
function EVP_DigestSignUpdate(AEVP_MD_CTX: PEVP_MD_CTX; d: Pointer; cnt: Integer): Integer; cdecl external LIB_CRYPTO name PREFIX + 'EVP_DigestSignUpdate';
function EVP_DigestVerify(AEVP_MD_CTX: PEVP_MD_CTX; sigret: Pointer; siglen: Integer; tbsret: Pointer; tbslen: Integer): Integer; cdecl external LIB_CRYPTO name PREFIX + 'EVP_DigestVerify';
function EVP_DigestVerifyInit(AEVP_MD_CTX: PEVP_MD_CTX; AEVP_PKEY_CTX: PEVP_PKEY_CTX; etype: PEVP_MD; impl: PEngine; AKey: PEVP_PKEY): Integer; cdecl external LIB_CRYPTO name PREFIX + 'EVP_DigestVerifyInit';
function EVP_DigestVerifyFinal(AEVP_MD_CTX: PEVP_MD_CTX; sig: Pointer; siglen: Integer): Integer; cdecl external LIB_CRYPTO name PREFIX + 'EVP_DigestVerifyFinal';
function EVP_MD_CTX_new: PEVP_MD_CTX; cdecl external LIB_CRYPTO name PREFIX + 'EVP_MD_CTX_new';
procedure EVP_MD_CTX_free(AEVP_MD_CTX: PEVP_MD_CTX); cdecl external LIB_CRYPTO name PREFIX + 'EVP_MD_CTX_free';
function EVP_PKEY_assign(AKey: PEVP_PKEY; Type_: Integer; Key: Pointer): Integer; cdecl external LIB_CRYPTO name PREFIX + 'EVP_PKEY_assign';
procedure EVP_PKEY_free(AKey: PEVP_PKEY); cdecl external LIB_CRYPTO name PREFIX + 'EVP_PKEY_free';
function EVP_PKEY_new: PEVP_PKEY; cdecl external LIB_CRYPTO name PREFIX + 'EVP_PKEY_new';
function EVP_sha1: PEVP_MD; cdecl external LIB_CRYPTO name PREFIX + 'EVP_sha1';
function EVP_sha224: PEVP_MD; cdecl external LIB_CRYPTO name PREFIX + 'EVP_sha224';
function EVP_sha256: PEVP_MD; cdecl external LIB_CRYPTO name PREFIX + 'EVP_sha256';
function EVP_sha384: PEVP_MD; cdecl external LIB_CRYPTO name PREFIX + 'EVP_sha384';
function EVP_sha512: PEVP_MD; cdecl external LIB_CRYPTO name PREFIX + 'EVP_sha512';
function EVP_sha3_224: PEVP_MD; cdecl external LIB_CRYPTO name PREFIX + 'EVP_sha3_224';
function EVP_sha3_256: PEVP_MD; cdecl external LIB_CRYPTO name PREFIX + 'EVP_sha3_256';
function EVP_sha3_384: PEVP_MD; cdecl external LIB_CRYPTO name PREFIX + 'EVP_sha3_384';
function EVP_sha3_512: PEVP_MD; cdecl external LIB_CRYPTO name PREFIX + 'EVP_sha3_512';

function HMAC(evp: pEVP_MD; key: PByte; key_len: Integer; data: PByte; data_len: Integer; md: PByte; var md_len: Integer): PByte; cdecl external LIB_CRYPTO name PREFIX + 'HMAC';

function PEM_read_bio_PrivateKey(ABIO: PBIO; X: PPEVP_PKEY; CB: TPEM_Password_Callback; UData: Pointer): PEVP_PKEY; cdecl external LIB_CRYPTO name PREFIX + 'PEM_read_bio_PrivateKey';
function PEM_read_bio_RSAPublicKey(ABIO: PBIO; x: PPRSA; CB: TPEM_Password_Callback; UData: Pointer): PEVP_PKEY; cdecl external LIB_CRYPTO name PREFIX + 'PEM_read_bio_RSAPublicKey';
function PEM_read_bio_RSA_PUBKEY(ABIO: PBIO; x: PPRSA; cb: TPEM_Password_Callback; u: pointer): PRSA; cdecl external LIB_CRYPTO name PREFIX + 'PEM_read_bio_RSA_PUBKEY';
function PEM_read_bio_X509(ABIO: PBIO; C509: PPX509; CallBack: TPEM_Password_Callback; UData: Pointer): PX509; cdecl external LIB_CRYPTO name PREFIX + 'PEM_read_bio_X509';

procedure RSA_free(RSA: PRSA); cdecl external LIB_CRYPTO name PREFIX + 'RSA_free';
function RSA_generate_key_ex(RSA: PRSA; Bits: Integer; e: Pointer; cb: PBN_GENCB): Integer; cdecl external LIB_CRYPTO name PREFIX + 'RSA_generate_key_ex';
function RSA_new: PRSA; cdecl external LIB_CRYPTO name PREFIX + 'RSA_new';

procedure X509_free(AX509: PX509); cdecl external LIB_CRYPTO name PREFIX + 'X509_free';
function _X509_get0_notAfter(AX509: PX509): PASN1_TIME; cdecl external LIB_CRYPTO name PREFIX + 'X509_get0_notAfter';
function _X509_get0_notBefore(AX509: PX509): PASN1_TIME; cdecl external LIB_CRYPTO name PREFIX + 'X509_get0_notBefore';
function X509_get_subject_name(AX509: PX509): PX509_NAME; cdecl external LIB_CRYPTO name PREFIX + 'X509_get_subject_name';
function X509_gmtime_adj(S: PASN1_TIME; Adj: LongInt): PASN1_TIME; cdecl external LIB_CRYPTO name PREFIX + 'X509_gmtime_adj';
function X509_new: PX509; cdecl external LIB_CRYPTO name PREFIX + 'X509_new';
function X509_set_issuer_name(AX509: PX509; Name: PX509_NAME): Integer; cdecl external LIB_CRYPTO name PREFIX + 'X509_set_issuer_name';
function X509_set_pubkey(AX509: PX509; AKey: PEVP_PKEY): Integer; cdecl external LIB_CRYPTO name PREFIX + 'X509_set_pubkey';
function X509_set_subject_name(AX509: PX509; Name: PX509_NAME): Integer; cdecl external LIB_CRYPTO name PREFIX + 'X509_set_subject_name';
function X509_set_version(AX509: PX509; Version: LongInt): Integer; cdecl external LIB_CRYPTO name PREFIX + 'X509_set_version';
function X509_set_serialNumber(AX509: PX509; serial: PASN1_INTEGER): Integer; cdecl external LIB_CRYPTO name PREFIX + 'X509_set_serialNumber';
function X509_sign(AX509: PX509; AKey: PEVP_PKEY; const Md: PEVP_MD): Integer; cdecl external LIB_CRYPTO name PREFIX + 'X509_sign';
function X509V3_EXT_conf_nid(Conf: PLHASH; CtX509: PX509V3_CTX; ext_nid: Integer; value: Pointer): PX509_EXTENSION; cdecl external LIB_CRYPTO name PREFIX + 'X509V3_EXT_conf_nid';
procedure X509_EXTENSION_free(Ext: PX509_EXTENSION); cdecl external LIB_CRYPTO name PREFIX + 'X509_EXTENSION_free';
function X509_NAME_add_entry_by_txt(Name: PX509_NAME; Field: MarshaledAString; Type_: Integer; Buf: Pointer; BufferSize: Integer; Loc: Integer; Set_: Integer): Integer; cdecl external LIB_CRYPTO name PREFIX + 'X509_NAME_add_entry_by_txt';
procedure X509_REQ_free(AX509_REQ: PX509_REQ); cdecl external LIB_CRYPTO name PREFIX + 'X509_REQ_free';
function X509_REQ_get_pubkey(AX509_REQ: PX509_REQ): PEVP_PKEY; cdecl external LIB_CRYPTO name PREFIX + 'X509_REQ_get_pubkey';
function _X509_REQ_get_subject_name(AAX509_REQ: PX509_REQ): PX509_NAME; cdecl external LIB_CRYPTO name PREFIX + 'X509_REQ_get_subject_name';
function X509_REQ_new: PX509_REQ; cdecl external LIB_CRYPTO name PREFIX + 'X509_REQ_new';
function X509_REQ_set_pubkey(AX509_REQ: PX509_REQ; AKey: PEVP_PKEY): Integer; cdecl external LIB_CRYPTO name PREFIX + 'X509_REQ_set_pubkey';
function X509_REQ_sign(AX509_REQ: PX509_REQ; AKey: PEVP_PKEY; const Md: PEVP_MD): Integer; cdecl external LIB_CRYPTO name PREFIX + 'X509_REQ_sign';
function X509_add_ext(X509: PX509; EX509: PX509_EXTENSION; loc: Integer): Integer; cdecl external LIB_CRYPTO name PREFIX + 'X509_add_ext';

function i2d_PrivateKey_bio(ABIO: PBIO; AKey: PEVP_PKEY): Integer; cdecl external LIB_CRYPTO name PREFIX + 'i2d_PrivateKey_bio';
function i2d_X509_bio(ABIO: PBIO; X509: PX509): Integer; cdecl external LIB_CRYPTO name PREFIX + 'i2d_X509_bio';

function RAND_bytes(buf: Pointer; num: Integer): Integer; cdecl external LIB_CRYPTO name PREFIX + 'RAND_bytes';

{ LibCrypto Helpers }
function X509_get_notBefore(AX509: PX509): PASN1_TIME;
function X509_get_notAfter(AX509: PX509): PASN1_TIME;
function X509_REQ_get_subject_name(AX509_REQ: PX509_REQ): PX509_NAME;

function EVP_MD_CTX_create: PEVP_MD_CTX;
procedure EVP_MD_CTX_destroy(AEVP_MD_CTX: PEVP_MD_CTX);

implementation

function X509_get_notBefore(AX509: PX509): PASN1_TIME;
begin
  if Assigned(AX509) then
    Result := _X509_get0_notBefore(AX509)
  else
    Result := nil;
end;

function X509_get_notAfter(AX509: PX509): PASN1_TIME;
begin
  if Assigned(AX509) then
    Result := _X509_get0_notAfter(AX509)
  else
    Result := nil;
end;

function X509_REQ_get_subject_name(AX509_REQ: PX509_REQ): PX509_NAME;
begin
  if Assigned(AX509_REQ) then
    Result := _X509_REQ_get_subject_name(AX509_REQ)
  else
    Result := nil;
end;

function EVP_MD_CTX_create: PEVP_MD_CTX;
begin
  Result := EVP_MD_CTX_new;
end;

procedure EVP_MD_CTX_destroy(AEVP_MD_CTX: PEVP_MD_CTX);
begin
  EVP_MD_CTX_free(AEVP_MD_CTX);
end;

end.
