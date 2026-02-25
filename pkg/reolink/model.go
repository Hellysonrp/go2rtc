package reolink

import "encoding/xml"

type LegacyLoginRes struct {
	XMLName    xml.Name `xml:"body"`
	Text       string   `xml:",chardata"`
	Encryption struct {
		Text         string `xml:",chardata"`
		Version      string `xml:"version,attr"`
		Type         string `xml:"type"`
		Nonce        string `xml:"nonce"`
		AuthTypeList struct {
			Text     string   `xml:",chardata"`
			AuthType []string `xml:"authType"`
		} `xml:"authTypeList"`
	} `xml:"Encryption"`
}

type ModernLoginReq struct {
	XMLName   xml.Name `xml:"body"`
	LoginUser struct {
		Text     string `xml:",chardata"`
		Version  string `xml:"version,attr"`
		UserName string `xml:"userName"`
		Password string `xml:"password"`
		UserVer  string `xml:"userVer"`
	} `xml:"LoginUser"`
	LoginNet struct {
		Text    string `xml:",chardata"`
		Version string `xml:"version,attr"`
		Type    string `xml:"type"`
		UdpPort string `xml:"udpPort"`
	} `xml:"LoginNet"`
}

func NewModernLoginReq(userHash, passHash string) []byte {
	req := ModernLoginReq{}
	req.LoginUser.Version = "1.1"
	req.LoginUser.UserName = userHash
	req.LoginUser.Password = passHash
	req.LoginUser.UserVer = "1"

	req.LoginNet.Version = "1.1"
	req.LoginNet.Type = "LAN"
	req.LoginNet.UdpPort = "0"

	b, err := xml.Marshal(req)
	if err != nil {
		// Construction is deterministic and schema-bound; panic on programmer error.
		panic(err)
	}
	return b
}

type ModernLoginRes struct {
	XMLName    xml.Name `xml:"body"`
	Text       string   `xml:",chardata"`
	DeviceInfo struct {
		Text            string `xml:",chardata"`
		Version         string `xml:"version,attr"`
		FirmVersion     string `xml:"firmVersion"`
		IOInputPortNum  string `xml:"IOInputPortNum"`
		IOOutputPortNum string `xml:"IOOutputPortNum"`
		DiskNum         string `xml:"diskNum"`
		Type            string `xml:"type"`
		DetailType      string `xml:"detailType"`
		ChannelNum      string `xml:"channelNum"`
		AudioNum        string `xml:"audioNum"`
		IpChannel       string `xml:"ipChannel"`
		AnalogChnNum    string `xml:"analogChnNum"`
		Resolution      struct {
			Text           string `xml:",chardata"`
			ResolutionName string `xml:"resolutionName"`
			Width          string `xml:"width"`
			Height         string `xml:"height"`
		} `xml:"resolution"`
		SecretCode        string `xml:"secretCode"`
		BootSecret        string `xml:"bootSecret"`
		Language          string `xml:"language"`
		SdCard            string `xml:"sdCard"`
		PtzMode           string `xml:"ptzMode"`
		TypeInfo          string `xml:"typeInfo"`
		SoftVer           string `xml:"softVer"`
		HardVer           string `xml:"hardVer"`
		PanelVer          string `xml:"panelVer"`
		HdChannel1        string `xml:"hdChannel1"`
		HdChannel2        string `xml:"hdChannel2"`
		HdChannel3        string `xml:"hdChannel3"`
		HdChannel4        string `xml:"hdChannel4"`
		Norm              string `xml:"norm"`
		OsdFormat         string `xml:"osdFormat"`
		B485              string `xml:"B485"`
		SupportAutoUpdate string `xml:"supportAutoUpdate"`
		UserVer           string `xml:"userVer"`
		FrameworkVer      string `xml:"FrameworkVer"`
		AuthMode          string `xml:"authMode"`
		Sleep             string `xml:"sleep"`
	} `xml:"DeviceInfo"`
	StreamInfoList struct {
		Text       string `xml:",chardata"`
		Version    string `xml:"version,attr"`
		StreamInfo struct {
			Text        string `xml:",chardata"`
			ChannelBits string `xml:"channelBits"`
			EncodeTable []struct {
				Text       string `xml:",chardata"`
				Type       string `xml:"type"`
				Resolution struct {
					Text   string `xml:",chardata"`
					Width  string `xml:"width"`
					Height string `xml:"height"`
				} `xml:"resolution"`
				VideoEncType     string `xml:"videoEncType"`
				DefaultFramerate string `xml:"defaultFramerate"`
				DefaultBitrate   string `xml:"defaultBitrate"`
				FramerateTable   string `xml:"framerateTable"`
				BitrateTable     string `xml:"bitrateTable"`
				DefaultGop       string `xml:"defaultGop"`
			} `xml:"encodeTable"`
		} `xml:"StreamInfo"`
	} `xml:"StreamInfoList"`
}

type Extension struct {
	XMLName    xml.Name `xml:"Extension"`
	Text       string   `xml:",chardata"`
	Version    string   `xml:"version,attr"`
	EncryptLen int      `xml:"encryptLen"`
	BinaryData int      `xml:"binaryData"`
	CheckPos   int      `xml:"checkPos"`
	CheckValue int      `xml:"checkValue"`
}

type StartStreamReq struct {
	XMLName xml.Name `xml:"body"`
	Text    string   `xml:",chardata"`
	Preview struct {
		Text       string `xml:",chardata"`
		Version    string `xml:"version,attr"`
		ChannelId  string `xml:"channelId"`
		Handle     string `xml:"handle"` // XML preview handle (0=main, 256=sub, 1024=extern per neolink); not the header stream type
		StreamType string `xml:"streamType"`
	} `xml:"Preview"`
}

type StopStreamReq struct {
	XMLName xml.Name `xml:"body"`
	Text    string   `xml:",chardata"`
	Preview struct {
		Text      string `xml:",chardata"`
		Version   string `xml:"version,attr"`
		ChannelId string `xml:"channelId"`
		Handle    string `xml:"handle"` // XML preview handle (0=main, 256=sub, 1024=extern per neolink); not the header stream type
	} `xml:"Preview"`
}
