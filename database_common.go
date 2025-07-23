//go:build !js && !plan9 && !wasip1

///////////////////////////////////////////////////////////////////////////////////////////////////
// DPS8M Proxy - database.go
// Copyright (c) 2025 Jeffrey H. Johnson
// Copyright (c) 2025 The DPS8M Development Team
// SPDX-License-Identifier: MIT
///////////////////////////////////////////////////////////////////////////////////////////////////

// DPS8M Proxy
package main

///////////////////////////////////////////////////////////////////////////////////////////////////

import (
	"bytes"
	"log"
	"time"

	"go.etcd.io/bbolt"
)

///////////////////////////////////////////////////////////////////////////////////////////////////

const dbEnabled = true

///////////////////////////////////////////////////////////////////////////////////////////////////

var (
	db                 *bbolt.DB
	dbPath             string
	persistedStartTime time.Time
)

var (
	metaBucketName      = []byte("meta")
	shutdownMarkerKey   = []byte("shutdown-marker")
	initialStartTimeKey = []byte("initial-start-time")
)

///////////////////////////////////////////////////////////////////////////////////////////////////

func initDB() {
	if dbPath == "" {
		return
	}

	defer func() {
		if r := recover(); r != nil {
			log.Fatalf("%sPANIC: Failure in database: %s",
				errorPrefix(), r) // LINTED: Fatalf
		}
	}()

	log.Printf("%sOpening statistics database: %s",
		dbPrefix(), dbPath)

	const dbPerm = 0o600
	var err error

	options := &bbolt.Options{
		Timeout:      1 * time.Second,
		FreelistType: bbolt.FreelistMapType,
	}

	db, err = bbolt.Open(dbPath, dbPerm, options)
	if err != nil {
		log.Fatalf("%sERROR: Failed to open statistics database: %v", //nolint:gocritic
			errorPrefix(), err) // LINTED: Fatalf
	}

	err = db.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(metaBucketName)
		if err != nil {
			return err
		}

		val := bucket.Get(shutdownMarkerKey)
		if bytes.Equal(val, []byte("0")) {
			log.Printf("%sUnclean database shutdown detected!", warnPrefix())
		} else {
			t, err := time.Parse(time.RFC3339, string(val))
			if err != nil {
				log.Printf("%sUnable to parse clean shutdown marker date '%s'.", warnPrefix(), string(val))
			} else {
				log.Printf("%sClean shutdown detected from %s.", dbPrefix(), t.Format("2006-Jan-02 15:04:05"))
			}
		}

		startTimeVal := bucket.Get(initialStartTimeKey)
		if startTimeVal == nil {
			if err := bucket.Put(initialStartTimeKey, []byte(startTime.Format(time.RFC3339))); err != nil {
				return err
			}
			persistedStartTime = startTime
		} else {
			pStartTime, err := time.Parse(time.RFC3339, string(startTimeVal))
			if err != nil {
				log.Printf("%sERROR: Failed to parse persisted start time: %v", warnPrefix(), err)
				persistedStartTime = startTime
			} else {
				persistedStartTime = pStartTime
			}
		}

		return bucket.Put(shutdownMarkerKey, []byte("0"))
	})
	if err != nil {
		log.Printf("%sERROR: Failed to initialize database metadata: %v", errorPrefix(), err)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func closeDB() {
	if db != nil {
		err := db.Update(func(tx *bbolt.Tx) error {
			bucket, err := tx.CreateBucketIfNotExists(metaBucketName)
			if err != nil {
				return err
			}

			return bucket.Put(shutdownMarkerKey, []byte(time.Now().Format(time.RFC3339)))
		})
		if err != nil {
			log.Printf("%sERROR: Failed to set clean shutdown marker: %v", errorPrefix(), err)
		}

		err = db.Close()
		if err != nil {
			log.Printf("%sERROR: Failed to close statistics database: %v", errorPrefix(), err)
		} else {
			log.Printf("%sStatistics database closed.", dbPrefix())
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// vim: set ft=go noexpandtab tabstop=4 cc=100 :
///////////////////////////////////////////////////////////////////////////////////////////////////
