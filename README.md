In this article we are going to discuss how to use the latest version of OpenSsl 1.1.1 with Delphi directly to create X.509 certificates, decode, verify, encode and sign Java Web Tokens and generate random data.  Additionally we will do this in a way that works on Delphi supported platforms including Windows, macOS, iOS, Android and Linux as well as all current compiler targets for 32 and 64-bit devices.

# Introduction

The OpenSsl library contains a wealth of useful tools that cover many aspects beyond just encryption and related protocol tasks.  OpenSsl is widely used to implement encryption and security over the network and the latest versions of OpenSsl support the newest standard TLS 1.3.

Developers often are reluctant to use OpenSsl in their projects because they must redistribute the library along with their project.  Also, it's nearly impossible to find examples of using it on Delphi platforms other than Windows.  The nice thing about using OpenSsl is that the interface for Delphi developers is consistent across all the platforms supported by Delphi.  Once you implement it on Windows, you can use that same approach on iOS, Android, Linux and macOS and expect that behavior to be consistent.  Additionally, OpenSsl has highly optimized internal crypto routines that typically outperform other crypto libraries on most platforms.  This is a consideration when building apps that spend the majority of their time communicating securely over the network or the Internet.

Here at Grijjy we use OpenSsl to implement TLS secure communications over the network when we implement HTTP/S and secure WebSockets.  We transmit and receive high-def video, audio and desktop sharing on all the OS platforms supported by Delphi in real-time using WebSockets and TLS with OpenSsl.  OpenSsl works well on multi-threaded, scalable socket servers and with bi-directional protocols like WebSockets with TCP or DTLS (datagram TLS) when transmitting data using the UDP protocol.  This allows us to have a common network stack to target all the platforms Delphi supports but to do this in a predicable manner.  

This is a fundamental issue with using the platform-native (or integrated) approach to HTTP/S and sockets when you need TLS.  While you get the advantage of not distributing OpenSsl, it can lead to unpredictable behavior from device to device and from machine to machine for simple tasks such as hashing, HTTP/S and other operations.  How one platform-native HTTP/S client handles asynchronous and/or synchronous requests or parallel threads, can vary widely.

Besides the obvious HTTP/S usage, OpenSsl contains a wealth of useful routines that you can use in your Delphi projects.  This article will cover just some of those use cases including using OpenSsl to create random bytes, creating your own X.509 certificates and using OpenSsl for handling Java Web Tokens (JWT) .   I like simple, straight-forward examples so this is by no means an exhaustive look at these subjects and is only intended as a primer for using OpenSsl with Delphi.  

## Java Web Tokens

Java Web Tokens are very popular as a way to provide the secure exchange of information between applications in the cloud over just exchanging regular access tokens.  They are widely used by many services and APIs available in the cloud like those offered by Google.

Traditionally, access tokens are used in OAuth models.  While both access tokens and JWTs are used for similar purposes they each have their own characteristics that make them suitable to certain scenarios.  With an access token, typically an implementation needs to track the token and lookup whether it has expired or what other detail is related to the token.  At Grijjy we typically cache tokens into memory and a database and then expire them (delete them) when their expiration interval is up.  Access tokens require that all the details of the token are maintained until it is no longer needed.

JWTs work a bit differently.  A typical JWT contains all the information related to the token within the token itself.  This includes enough information validate that the token is authorized and not expired.  JWTs can also contain custom payloads specific to your application.  For this purposes they can avoid a round trip to a cache of tokens in memory or in the database for each request.  However, processing JWTs with each request and validating them can be a time consuming thing.  Quite a few APIs end up mixing both access tokens and JWTs for their APIs.

Personally I feel that JWTs can be very efficient, especially if you validate them one time and then cache them into memory until their expiration is up.  That way, with each request you are not validating the entire signature of the JWT again but instead just looking up to see if you previously validated the JWT.  A full discussion of tokens is beyond the scope of this article, but we will demonstrate JWTs using at least one hash scheme with OpenSsl.

**Note:** This is not meant as an exhaustive look at JWTs.  We are only demonstrating one algorithm.  There are other nice libraries for handling JWTs in Delphi.  Our intent is to show how OpenSsl can do this in a simple, straightforward and cross-platform way.

### Decoding and verifying the signature of a JWT

Decoding a JWT is a straightforward process of separating the entire token into 3 logical parts; the header, the payload and the signature.  For simplicity sake we created a small helper record in Delphi to assist with decoding, verifying, encoding and signing the JWT using OpenSsl.

```pascal
  { Java Web Token }
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

    { Decodes a java web token into the header, payload and signature parts

      Parameters:
        AJavaWebToken: the encoded token

      Returns:
        True if the token was decoded, False otherwise }
    function Decode(const AJavaWebToken: String): Boolean;

    { Signs the java web token using the provided private key or secret

      Parameters:
        APrivateKey: the private key or secret
        AJavaWebToken: the encoded and signed token

      Returns:
        True if the token was successfully signed along with the resulting token, False otherwise }
    function Sign(const APrivateKey: TBytes; out AJavaWebToken: String): Boolean;

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
        AJavaWebToken: the encoded token
        APrivateKey: the private key or secret

      Returns:
        True if the token signature was verified, False otherwise }
    function VerifyWithPrivateKey(const AJavaWebToken: String; const APrivateKey: TBytes): Boolean; overload;

    { Verifies the token was signed with the provided private key

      Parameters:
        APrivateKey: the private key or secret

      Returns:
        True if the token signature was verified, False otherwise }
    function VerifyWithPrivateKey(const APrivateKey: TBytes): Boolean; overload;

    { Verifies the token was signed with a private key associated with the provided public key

      Parameters:
        AJavaWebToken: the encoded token
        APublicKey: the public key

      Returns:
        True if the token signature was verified, False otherwise

      Note: The public key can be in the form of a PEM formatted RSA PUBLIC KEY or CERTIFICATE }
    function VerifyWithPublicKey(const AJavaWebToken: String; const APublicKey: TBytes): Boolean;
  public
    { Web token header }
    property Header: TBytes read FHeader write FHeader;

    { Web token data payload }
    property Payload: TBytes read FPayload write FPayload;

    { Signature for the token }
    property Signature: TBytes read FSignature write FSignature;
  end;
```

To keep things simple, the record contains a method called ```Decode()``` that separates the token into a header, payload and signature.  You can also call the method ```VerifyWithPublicKey()``` to directly verify that the JWT was signed using a private key that matches the provided public key.

We have included an example Firemonkey application and source code demonstrates the process of decoding and verifying the signature.

![](https://bloggrijjy.files.wordpress.com/2020/08/decode-jwt.jpg)

In the above example, the Encoded memo contains the entire Java Web Token.  By clicking decode, it decodes the header and payload and the signature.  Clicking verify will check to make sure that the JWT is signed properly by checking the signature against the public key that is provided under the Certificate tab in the example application.

Internally the routine ```VerifyWithPublicKey()``` uses the OpenSsl method ```PEM_read_bio_RSAPublicKey``` to load the PEM public key certificate and the ```EVP_DigestVerify``` APIs to verify the signature is correct.

### Encoding and signing a JWT

Encoding a JWT follows a similar approach.  You supply the header and the payload and it this content is signed to form a complete encoded Java Web Token.

Our example application also demonstrates the ability to encode and sign the JWT.  Internally it OpenSsl methods ```PEM_read_bio_PrivateKey``` to load the private key and the ```EVP_DigestSign``` related methods to create the signature for the JWT.  

![](https://bloggrijjy.files.wordpress.com/2020/08/encode-jwt.jpg)

Our helper only handles RS256 signing and verification methods and Java Web Tokens support many other signing strategies.  These other algorithms could easily be adapted to the helper using other OpenSsl support methods.

## X.509 Self-Signed Certificates

Another useful capability of the OpenSsl library is the ability to generate your own X.509 self-signed certificates.  This involves using APIs including ```RSA_generate_key_ex```  and ```X509_sign``` from the crypto libraries and then converting the resulting certificate and private key into a PEM certificate.

Additionally you can create an X.509 certificate based upon an existing Certificate Authority (CA) using the same APIs.  For simplicity we demonstrate this capability using our TgoOpenSslHelper class.

```pascal
  TgoOpenSSLHelper = class
  public
    { Creates a X.509 self-signed certificate

      Parameters:
        ACountry: the country value of the certificate
        AState: the state value of the certificate
        ALocality: the locality value of the certificate
        AOrganization: the org value of the certificate
        AOrgUnit: the org unit value of the certificate
        ACommonName: the common name value of the certificate
        AServerName: the given DNS name for the certificate (optional)
        AExpiresDays: the number of days before the certificate will expire
        ACertificate: the resulting X.509 certificate
        APrivateKey: the resulting private key

      Returns:
        True if the certificate pair was created, False otherwise }
    class function CreateSelfSignedCert_X509(
      const ACountry, AState, ALocality, AOrganization, AOrgUnit, ACommonName: String;
      const AServerName: String; const AExpiresDays: Integer;
      out ACertificate, APrivateKey: TBytes): Boolean; static;

    { Creates a X.509 certificate signed by the provided CA

      Parameters:
        ACertificateCA: the certificate authority certificate
        APrivateKeyCA: the certificate authority private key
        APassword: the password for the private key (optional)
        ACountry: the country value of the certificate
        AState: the state value of the certificate
        ALocality: the locality value of the certificate
        AOrganization: the org value of the certificate
        AOrgUnit: the org unit value of the certificate
        ACommonName: the common name value of the certificate
        AServerName: the given DNS name for the certificate (optional)
        AExpiresDays: the number of days before the certificate will expire
        ACertificate: the resulting X.509 certificate
        APrivateKey: the resulting private key

      Returns:
        True if the certificate pair was created, False otherwise }
    class function CreateSelfSignedCert_X509CA(const ACertificateCA, APrivateKeyCA: TBytes; const APassword: String;
      const ACountry, AState, ALocality, AOrganization, AOrgUnit, ACommonName: String;
      const AServerName: String; const AExpiresDays: Integer;
      out ACertificate, APrivateKey: TBytes): Boolean; static;
  end;
```

The class exposes 2 class methods for creating X.509 self-signed certificates using OpenSsl, one that creates self-signed certificates without a CA and another that uses a CA.

Our example application demonstrates the creation of simple X.509 certificates in Delphi:

![](https://bloggrijjy.files.wordpress.com/2020/08/x509-cert.jpg)

When you create the certificate, the information you provided is included in the construction of the certificate.  If you are using the certificate with a server that implements SNI (server name indication), then the server name of the certificate needs to be specified.

The examples in the helper class also demonstrates chaining PEM certificates using OpenSsl if you are using one or more intermediate certificate authority certificates.

## Crypto-safe Random

OpenSsl relies on generating crypto-secure random numbers internally as a basis for generating prime numbers used in the production of public and private key pairs.  These routines have been tested over many years to make sure they are truly crypto-safe random number generators.

You can use these same routines inside of Delphi if you want to generate random strings, numbers or bytes.  Our TgoOpenSslHelper class exposes various routines that demonstrate the randomizer.

```pascal
  TgoOpenSSLHelper = class
  public
    { Generates a crypto-safe random buffer of bytes

      Parameters:
        ASize: the length in bytes

      Returns:
        Bytes of random data }
    class function RandomBytes(const ASize: Integer): TBytes; static;

    { Generates a crypto-safe random string

      Parameters:
        ACharset: a string of approved characters
        ASize: the length in bytes

      Returns:
        String of random data }
    class function RandomString(const ACharset: String; const ASize: Integer): String; overload; static;

    { Generates a crypto-safe random string

      Parameters:
        ASize: the length in bytes

      Returns:
        String of random data }
    class function RandomString(const ASize: Integer): String; overload; static;

    { Generates a crypto-safe random string of characters only

      Parameters:
        ASize: the length in bytes

      Returns:
        String of random data }
    class function RandomChars(const ASize: Integer): String; static;

    { Generates a crypto-safe lowercase random string

      Parameters:
        ASize: the length in bytes

      Returns:
        String of random data }
    class function RandomLowerString(const ASize: Integer): String; static;

    { Generates a crypto-safe random string of lowercase characters only

      Parameters:
        ASize: the length in bytes

      Returns:
        String of random data }
    class function RandomLowerChars(const ASize: Integer): String; static;

    { Generates a crypto-safe random string of numbers

      Parameters:
        ASize: the length in bytes

      Returns:
        String of random data }
    class function RandomDigits(const ASize: Integer): String; static;
  end;
```

If you need to generate random sequences the `rand()` method in OpenSsl can be very useful.  We also demonstrate how this could be used in the example application:

![](https://bloggrijjy.files.wordpress.com/2020/08/random.jpg)

## Building OpenSsl for Delphi platforms

Developers often ask us how to build, link and use OpenSsl from all the platforms Delphi can support.  The process of building OpenSsl is fairly complicated for the platforms that Delphi supports.  

In a future article we may cover this process for each platform.  There are numerous steps on some platforms and custom scripts to produce the desired compiler output for mobile platforms.  For the current examples in this article, we provide the pre-built binaries for the platforms that use a dynamic library (Win32, Win64, macOS-32, Linux) and also those that utilize a static library (Android32, Android64, iOS, macOS-64) for OpenSsl.

## Conclusion

OpenSsl has evolved over a long period of time and the latest versions contain various useful routines that you can use across your cross-platform Delphi projects.  

There are some very nice third-party, Delphi specific crypto libraries available that are pure Delphi.  While many of these libraries are excellent and I have used them in projects in the past, they tend not to share the performance of OpenSsl.

Additionally, depending upon where you are located in the world you might encounter export restrictions that limit what crypto libraries you can utilize without government scrutiny.  Here in the US, OpenSsl is considered approved domestically and can be exported.  We do a significant amount of development for US based government and military agencies and OpenSsl offers FIPS compliance and certification.  The next generation of OpenSsl will also support the newest FIPS requirements (planned).  These rules and regulations may impact your project as well if you import into or export from certain localities.

We hope you enjoyed this primer on using OpenSsl on all the platforms that Delphi supports.