package Structs

type DataS struct {
	Action int   `json:"action"`
	User   UserS `json:"user"`
}
type UserS struct {
	Name     []byte `json:"name"`
	Password []byte `json:"password"`
	Archivo  FileS  `json:"archivo"`
}

type FileS struct {
	NameFile []byte `json:"nameFile"`
	NameH    []byte `json:"nameH"`
	Peso     int    `json:"peso"`
	Data     []byte `json:"data"`
	Token    []byte `json:"token"`
}

type RespuestaS struct {
	ActAny int
	ErrNum int
	Msg    string
	File   FileS
	Data   []byte
}
