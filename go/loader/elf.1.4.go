// +build go1.4

package loader

import "github.com/lunixbochs/usercorn/go/models"

func (e *ElfLoader) getSymbols() ([]models.Symbol, error) {
	symbols, err := e.getSymbolsCommon()
	if err != nil {
		return nil, err
	}
	dyn, _ := e.file.DynamicSymbols()
	for _, s := range dyn {
		symbols = append(symbols, models.Symbol{
			Name:    s.Name,
			Start:   s.Value,
			End:     s.Value + s.Size,
			Dynamic: true,
		})
	}
	return symbols, nil
}
