unit FMain;

interface

uses
  System.SysUtils,
  System.Types,
  System.UITypes,
  System.Classes,
  System.Variants,
  FMX.Types,
  FMX.Graphics,
  FMX.Controls,
  FMX.Forms,
  FMX.Dialogs,
  FMX.TabControl,
  FMX.StdCtrls,
  FMX.Gestures,
  FMX.Controls.Presentation,
  FMX.Memo.Types,
  FMX.ScrollBox,
  FMX.Memo,
  FMX.Edit,
  Grijjy.OpenSsl_11,
  Grijjy.OAuth2,
  Grijjy.BinaryCoding;

type
  TFormMain = class(TForm)
    HeaderToolBar: TToolBar;
    ToolBarLabel: TLabel;
    TabControlMain: TTabControl;
    TabItemDecodeJWT: TTabItem;
    TabItemEncodeJWT: TTabItem;
    TabItemJWTCertificate: TTabItem;
    GestureManager1: TGestureManager;
    MemoJWT1: TMemo;
    MemoHeader1: TMemo;
    MemoPayload1: TMemo;
    LabelEncoded1: TLabel;
    LabelHeader1: TLabel;
    LabelPayload1: TLabel;
    ButtonDecodeJWT: TButton;
    LabelSignature1: TLabel;
    MemoSignature1: TMemo;
    ButtonVerifyJWT: TButton;
    LabelPublicKey: TLabel;
    MemoPublicKey: TMemo;
    LabelPrivateKey: TLabel;
    MemoPrivateKey: TMemo;
    MemoJWT2: TMemo;
    LabelEncoded2: TLabel;
    LabelHeader2: TLabel;
    MemoHeader2: TMemo;
    LabelPayload2: TLabel;
    MemoPayload2: TMemo;
    LabelSignature2: TLabel;
    MemoSignature2: TMemo;
    ButtonEncodeJWT: TButton;
    ButtonResetDecode: TButton;
    ButtonResetEncode: TButton;
    TabItemX509Cert: TTabItem;
    EditCountry: TEdit;
    LabelCountry: TLabel;
    LabelState: TLabel;
    EditState: TEdit;
    LabelLocality: TLabel;
    EditLocality: TEdit;
    LabelOrganization: TLabel;
    EditOrganization: TEdit;
    LabelOrgUnit: TLabel;
    EditOrgUnit: TEdit;
    LabelCommonName: TLabel;
    EditCommonName: TEdit;
    LabelServerName: TLabel;
    EditServerName: TEdit;
    LabelExpiresDays: TLabel;
    EditExpiresDays: TEdit;
    LabelX509Certificate: TLabel;
    MemoX509Certificate: TMemo;
    LabelX509PrivateKey: TLabel;
    MemoX509PrivateKey: TMemo;
    ButtonCreateX509: TButton;
    TabItemRandom: TTabItem;
    LabelRandomString: TLabel;
    EditRandomString: TEdit;
    ButtonRandomString: TButton;
    LabelRandomDigits: TLabel;
    EditRandomDigits: TEdit;
    ButtonRandomDigits: TButton;
    procedure FormCreate(Sender: TObject);
    procedure FormGesture(Sender: TObject; const EventInfo: TGestureEventInfo;
      var Handled: Boolean);
    procedure ButtonDecodeJWTClick(Sender: TObject);
    procedure ButtonVerifyJWTClick(Sender: TObject);
    procedure ButtonEncodeJWTClick(Sender: TObject);
    procedure ButtonResetDecodeClick(Sender: TObject);
    procedure ButtonResetEncodeClick(Sender: TObject);
    procedure ButtonCreateX509Click(Sender: TObject);
    procedure ButtonRandomStringClick(Sender: TObject);
    procedure ButtonRandomDigitsClick(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  FormMain: TFormMain;

implementation

{$R *.fmx}

procedure TFormMain.FormCreate(Sender: TObject);
begin
  { This defines the default active tab at runtime }
  TabControlMain.ActiveTab := TabItemDecodeJWT;
end;

procedure TFormMain.FormGesture(Sender: TObject;
  const EventInfo: TGestureEventInfo; var Handled: Boolean);
begin
{$IFDEF ANDROID}
  case EventInfo.GestureID of
    sgiLeft:
    begin
      if TabControl1.ActiveTab <> TabControl1.Tabs[TabControl1.TabCount-1] then
        TabControl1.ActiveTab := TabControl1.Tabs[TabControl1.TabIndex+1];
      Handled := True;
    end;

    sgiRight:
    begin
      if TabControl1.ActiveTab <> TabControl1.Tabs[0] then
        TabControl1.ActiveTab := TabControl1.Tabs[TabControl1.TabIndex-1];
      Handled := True;
    end;
  end;
{$ENDIF}
end;

function BytesToHex(const ABuffer: TBytes): String;
begin
  SetLength(Result, Length(ABuffer) * 2);
  BinToHex(PAnsiChar(ABuffer), PChar(Result), Length(ABuffer));
end;

function HexToBytes(const ABuffer: String): TBytes;
begin
  SetLength(Result, Length(ABuffer) div 2);
  HexToBin(PChar(ABuffer), PAnsiChar(Result), Length(Result));
end;

procedure TFormMain.ButtonDecodeJWTClick(Sender: TObject);
var
  JWT: TgoJWT;
begin
  if JWT.Decode(MemoJWT1.Text) then
  begin
    MemoHeader1.Text := StringOf(JWT.Header);
    MemoPayload1.Text := StringOf(JWT.Payload);
    MemoSignature1.Text := BytesToHex(JWT.Signature);
    ShowMessage('Decoded!');
  end
  else
    ShowMessage('Failed Decoded!');
end;

procedure TFormMain.ButtonEncodeJWTClick(Sender: TObject);
var
  JavaWebToken: String;
  PrivateKey: RawByteString;
  PrivateKeyBytes: TBytes;
  JWT: TgoJWT;
begin
  { Extract the Private Key from the memo }
  PrivateKey := RawByteString(MemoPrivateKey.Text);
  SetLength(PrivateKeyBytes, Length(PrivateKey));
  Move(PrivateKey[1], PrivateKeyBytes[0], Length(PrivateKey));

  { Initialize the JWT }
  JWT.Initialize(MemoHeader2.Text, MemoPayload2.Text);

  { Sign the JWT }
  if JWT.Sign(PrivateKeyBytes, JavaWebToken) then
  begin
    MemoJWT2.Text := JavaWebToken;
    MemoSignature2.Text := BytesToHex(JWT.Signature);
    ShowMessage('Encoded!');
  end
  else
    ShowMessage('Failed Encoded!');
end;

procedure TFormMain.ButtonVerifyJWTClick(Sender: TObject);
var
  JWT: TgoJWT;
  JavaWebToken: String;
  PublicKey: RawByteString;
  JavaWebTokenBytes, PublicKeyBytes: TBytes;
begin
  if JWT.Decode(MemoJWT1.Text) then
  begin
    { Extract the JWT from the memo }
    JavaWebToken := MemoJWT1.Text;
    SetLength(JavaWebTokenBytes, Length(JavaWebToken));
    Move(JavaWebToken[1], JavaWebTokenBytes[0], Length(JavaWebToken));

    { Extract the Public Key from the memo }
    PublicKey := RawByteString(MemoPublicKey.Text);
    SetLength(PublicKeyBytes, Length(PublicKey));
    Move(PublicKey[1], PublicKeyBytes[0], Length(PublicKey));

    { Verify the JWT was signed using the Public Key }
    if JWT.VerifyWithPublicKey(JavaWebToken, PublicKeyBytes) then
      ShowMessage('Verified!')
    else
      ShowMessage('Failed Verify!');
  end;
end;

procedure TFormMain.ButtonResetDecodeClick(Sender: TObject);
begin
  MemoHeader1.Text := '';
  MemoPayload1.Text := '';
  MemoSignature1.Text := '';
end;

procedure TFormMain.ButtonResetEncodeClick(Sender: TObject);
begin
  MemoJWT2.Text := '';
  MemoSignature2.Text := '';
end;

procedure TFormMain.ButtonCreateX509Click(Sender: TObject);
var
  Certificate, PrivateKey: TBytes;
begin
  if TgoOpenSSLHelper.CreateSelfSignedCert_X509(
    EditCountry.Text,
    EditState.Text,
    EditLocality.Text,
    EditOrganization.Text,
    EditOrgUnit.Text,
    EditCommonName.Text,
    EditServerName.Text,
    EditExpiresDays.Text.ToInteger,
    Certificate, PrivateKey) then
  begin
    MemoX509Certificate.Text := StringOf(Certificate);
    MemoX509PrivateKey.Text := StringOf(PrivateKey);
    ShowMessage('Created!');
  end
  else
    ShowMessage('Failed Created!');
end;

procedure TFormMain.ButtonRandomDigitsClick(Sender: TObject);
begin
  EditRandomDigits.Text := TgoOpenSSLHelper.RandomDigits(32);
end;

procedure TFormMain.ButtonRandomStringClick(Sender: TObject);
begin
  EditRandomString.Text := TgoOpenSSLHelper.RandomString(32);
end;

end.
