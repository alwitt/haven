// Package main - Atlas GORM migration support binary
package main

import (
	"fmt"

	"ariga.io/atlas-provider-gorm/gormschema"
	"github.com/alwitt/haven/db"
	"github.com/apex/log"
)

func main() {
	stmts, err := gormschema.New("postgres").Load(
		&db.SystemEventAuditDBEntry{},
		&db.SystemParamsDBEntry{},
		&db.EncryptionKeyDBEntry{},
		&db.RecordDBEntry{},
		&db.RecordVersionDBEntry{},
	)
	if err != nil {
		log.WithError(err).Fatal("Failed to load GORM models")
	}
	fmt.Printf("%s\n", stmts)
}
