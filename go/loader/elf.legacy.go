// +build !go1.4

package loader

import "github.com/lunixbochs/usercorn/go/models"

func (e *ElfLoader) getSymbols() ([]models.Symbol, error) {
	return e.getSymbolsCommon()
}
