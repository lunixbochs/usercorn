package common

import "errors"

var UnknownUnpackType = errors.New("kernel.Unpack() does not support type")
var NoUnpackHandler = errors.New("no kernel.Unpack() handler defined")
