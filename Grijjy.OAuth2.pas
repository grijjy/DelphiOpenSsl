unit Grijjy.OAuth2;
{ Routines for handling OAuth2 and JSON Web Tokens }

{ Note: Currently only supports RS256 }

{$INCLUDE 'Grijjy.inc'}

interface

uses
  System.SysUtils,
  System.NetEncoding,
  Grijjy.System;

const
  { Headers for algorithms }
  JWT_RS256 = '{"alg":"RS256","typ":"JWT"}';

type
  { OAuth/2 header }
  TgoOAuth2Header = record
  private
    FAlg: String;
    FTyp: String;
  public
    { Initialize the header parameters }
    procedure Initialize;

    { Decodes json web token header as json }
    function FromJson(const AHeader: TBytes): Boolean;

    { Returns a Json string of the header }
    function ToJson: String;
  public
    { Signature algorithm }
    property Alg: String read FAlg write FAlg;

    { Token type  }
    property Typ: String read FTyp write FTyp;
  end;

  { OAuth/2 claim set }
  TgoOAuth2ClaimSet = record
  private
    FIss: String;
    FSub: String;
    FAud: String;
    FExp: TDateTime;
    FIat: TDateTime;
  public
    { Initialize the claim set parameters }
    procedure Initialize;

    { Decodes json web token payload as json }
    function FromJson(const APayload: TBytes): Boolean;

    { Returns a Json string of the claim set }
    function ToJson(const AExpiresInSec: Integer): String;
  public
    { The issuer of the claim }
    property Iss: String read FIss write FIss;

    { The subject claim (sub) normally describes to whom or to which application the JWT is issued }
    property Sub: String read FSub write FSub;

    { The audience (aud) identifies the authorization server as an intended audience }
    property Aud: String read FAud write FAud;

    { The expiration time (exp) of the JWT }
    property Exp: TDateTime read FExp write FExp;

    { The issued at claim (iat) can be used to store the time at which the JWT is created }
    property Iat: TDateTime read FIat write FIat;
  end;

type
  { JSON Web Token }
  TgoJWT = record
  private
    FHeader: TBytes;
    FPayload: TBytes;
    FSignature: TBytes;
  public
    { Initializes the token with the provided header

      Parameters:
        AHeader: the header for the token }
    procedure Initialize(const AHeader: String); overload;

    { Initializes the token with the provided header and payload

      Parameters:
        AHeader: the header for the token
        APayload: the data payload for the token }
    procedure Initialize(const AHeader, APayload: String); overload;

    { Decodes a json web token into the header, payload and signature parts

      Parameters:
        AJsonWebToken: the encoded token

      Returns:
        True if the token was decoded, False otherwise }
    function Decode(const AJsonWebToken: String): Boolean;

    { Signs the json web token using the provided private key or secret

      Parameters:
        APrivateKey: the private key or secret
        AJsonWebToken: the encoded and signed token

      Returns:
        True if the token was successfully signed along with the resulting token, False otherwise }
    function Sign(const APrivateKey: TBytes; out AJsonWebToken: String): Boolean;

    { Verifies the token was signed with the provided private key

      Parameters:
        AData: the data that was signed
        ASignature: the signature for the data
        APrivateKey: the private key or secret

      Returns:
        True if the token signature was verified, False otherwise }
    function VerifyWithPrivateKey(const AData, ASignature: TBytes; const APrivateKey: TBytes): Boolean; overload;

    { Verifies the token was signed with the provided private key

      Parameters:
        AJsonWebToken: the encoded token
        APrivateKey: the private key or secret

      Returns:
        True if the token signature was verified, False otherwise }
    function VerifyWithPrivateKey(const AJsonWebToken: String; const APrivateKey: TBytes): Boolean; overload;

    { Verifies the token was signed with the provided private key

      Parameters:
        APrivateKey: the private key or secret

      Returns:
        True if the token signature was verified, False otherwise }
    function VerifyWithPrivateKey(const APrivateKey: TBytes): Boolean; overload;

    { Verifies the token was signed with a private key associated with the provided public key

      Parameters:
        AJsonWebToken: the encoded token
        APublicKey: the public key

      Returns:
        True if the token signature was verified, False otherwise

      Note: The public key can be in the form of a PEM formatted RSA PUBLIC KEY or CERTIFICATE }
    function VerifyWithPublicKey(const AJsonWebToken: String; const APublicKey: TBytes): Boolean;
  public
    { Web token header }
    property Header: TBytes read FHeader write FHeader;

    { Web token data payload }
    property Payload: TBytes read FPayload write FPayload;

    { Signature for the token }
    property Signature: TBytes read FSignature write FSignature;
  end;

implementation

uses
  System.DateUtils,
  Grijjy.BinaryCoding,
  Grijjy.OpenSsl_11,
  Grijjy.Bson;

{ Helpers }

{ Decode Base64 encoded string - Base64url RFC 4648 }
function Base64UrlDecode(const AEncodedString: String): TBytes;
var
  S: String;
begin
  S := AEncodedString;
  S := S + StringOfChar('=', (4 - Length(AEncodedString) mod 4) mod 4);
  S := S.Replace('-', '+', [rfReplaceAll])
    .Replace('_', '/', [rfReplaceAll]);
  Result := TNetEncoding.Base64.DecodeStringToBytes(S);
end;

{ Encode Base64 bytes - Base64url RFC 4648 }
function Base64UrlEncode(const ADecodedBytes: TBytes): String;
var
  S: String;
begin
  S := TNetEncoding.Base64.EncodeBytesToString(ADecodedBytes);
  S := S.Replace(#13#10, '', [rfReplaceAll])
    .Replace(#13, '', [rfReplaceAll])
    .Replace(#10, '', [rfReplaceAll])
    .TrimRight(['='])
    .Replace('+', '-', [rfReplaceAll])
    .Replace('/', '_', [rfReplaceAll]);
  Result := S;
end;

{ TgoOAuth2Header }

procedure TgoOAuth2Header.Initialize;
begin
  FAlg := 'RS256';
  FTyp := 'JWT';
end;

function TgoOAuth2Header.FromJson(const AHeader: TBytes): Boolean;
var
  BsonDoc: TgoBsonDocument;
begin
  try
    BsonDoc := TgoBsonDocument.Load(AHeader);
    FAlg := BsonDoc['alg'];
    FTyp := BsonDoc['typ'];
    Result := True;
  except
    on e: exception do
      Result := False;
  end;
end;

function TgoOAuth2Header.ToJson: String;
var
  BsonDoc: TgoBsonDocument;
begin
  BsonDoc := TgoBsonDocument.Create;
  BsonDoc['alg'] := FAlg;
  BsonDoc['typ'] := FTyp;
  Result := BsonDoc.ToJson;
end;

{ TgoOAuth2ClaimSet }

procedure TgoOAuth2ClaimSet.Initialize;
begin

end;

function TgoOAuth2ClaimSet.FromJson(const APayload: TBytes): Boolean;
var
  BsonDoc: TgoBsonDocument;
begin
  try
    BsonDoc := TgoBsonDocument.Load(APayload);
    FIss := BsonDoc['iss'];
    FSub := BsonDoc['sub'];
    FAud := BsonDoc['aud'];
    FExp := BsonDoc['exp'];
    FIat := BsonDoc['iat'];
    Result := True;
  except
    on e: exception do
      Result := False;
  end;
end;

function TgoOAuth2ClaimSet.ToJson(const AExpiresInSec: Integer): String;
var
  BsonDoc: TgoBsonDocument;
begin
  BsonDoc := TgoBsonDocument.Create;
  BsonDoc['iss'] := FIss;
  BsonDoc['sub'] := FSub;
  BsonDoc['aud'] := FAud;
  BsonDoc['exp'] := DateTimeToUnix(TTimeZone.Local.ToUniversalTime(IncSecond(FIat, AExpiresInSec)));
  BsonDoc['iat'] := DateTimeToUnix(TTimeZone.Local.ToUniversalTime(FIat));
  Result := BsonDoc.ToJson;
end;

{ TgoJWT }

procedure TgoJWT.Initialize(const AHeader: String);
begin
  FHeader := TEncoding.UTF8.GetBytes(AHeader);
end;

procedure TgoJWT.Initialize(const AHeader, APayload: String);
begin
  FHeader := TEncoding.UTF8.GetBytes(AHeader);
  FPayload := TEncoding.UTF8.GetBytes(APayload);
end;

function TgoJWT.Decode(const AJsonWebToken: String): Boolean;
var
  Parts: TArray<String>;
begin
  { Must contain 3 parts }
  Parts := AJsonWebToken.Split(['.']);
  if Length(Parts) < 3 then
    Exit(False);

  FHeader := Base64UrlDecode(Parts[0]);
  FPayload := Base64UrlDecode(Parts[1]);
  FSignature := Base64UrlDecode(Parts[2]);
  Result := True;
end;

function TgoJWT.Sign(const APrivateKey: TBytes; out AJsonWebToken: String): Boolean;
var
  Data: String;
begin
  Data := Base64UrlEncode(FHeader) + '.' + Base64UrlEncode(FPayload);
  if not TgoOpenSSLHelper.Sign_RSASHA256(TEncoding.Utf8.GetBytes(Data), APrivateKey, FSignature) then
    Exit(False);

  AJsonWebToken := Data + '.' + Base64UrlEncode(FSignature);
  Result := True;
end;

function TgoJWT.VerifyWithPrivateKey(const AData, ASignature: TBytes; const APrivateKey: TBytes): Boolean;
var
  Signature: TBytes;
begin
  if TgoOpenSSLHelper.Sign_RSASHA256(AData, APrivateKey, Signature) then
    Result := (Signature = ASignature)
  else
    Result := False;
end;

function TgoJWT.VerifyWithPrivateKey(const AJsonWebToken: String; const APrivateKey: TBytes): Boolean;
var
  Parts: TArray<String>;
  Data, Signature: TBytes;
begin
  { Must contain 3 parts }
  Parts := AJsonWebToken.Split(['.']);
  if Length(Parts) < 3 then
    Exit(False);

  Data := TEncoding.Utf8.GetBytes(Parts[0] + '.' + Parts[1]);
  Signature := Base64UrlDecode(Parts[2]);
  Result := VerifyWithPrivateKey(Data, Signature, APrivateKey);
end;

function TgoJWT.VerifyWithPrivateKey(const APrivateKey: TBytes): Boolean;
var
  Data: String;
begin
  Data := Base64UrlEncode(FHeader) + '.' + Base64UrlEncode(FPayload);
  Result := VerifyWithPrivateKey(TEncoding.Utf8.GetBytes(Data), FSignature, APrivateKey);
end;

function TgoJWT.VerifyWithPublicKey(const AJsonWebToken: String; const APublicKey: TBytes): Boolean;
var
  Parts: TArray<String>;
  Header, Payload: TBytes;
  Signature: TBytes;
begin
  { Must contain 3 parts }
  Parts := AJsonWebToken.Split(['.']);
  if Length(Parts) < 3 then
    Exit(False);

  Header := TEncoding.UTF8.GetBytes(Parts[0]);
  Payload := TEncoding.UTF8.GetBytes(Parts[1]);
  Signature := Base64UrlDecode(Parts[2]);
  Result := TgoOpenSSLHelper.Verify_RSASHA256(Header, Payload, Signature, APublicKey);
end;

end.
