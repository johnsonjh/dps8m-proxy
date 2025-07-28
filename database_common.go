//go:build !js && !plan9 && !wasip1

///////////////////////////////////////////////////////////////////////////////////////////////////
// DPS8M Proxy - database_common.go
// Copyright (c) 2025 Jeffrey H. Johnson
// Copyright (c) 2025 The DPS8M Development Team
// SPDX-License-Identifier: MIT
// scspell-id: 77a5f39c-6bd1-11f0-8f95-80ee73e9b8e7
///////////////////////////////////////////////////////////////////////////////////////////////////

// DPS8M Proxy
package main

///////////////////////////////////////////////////////////////////////////////////////////////////

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"sync/atomic"
	"time"

	"go.etcd.io/bbolt"
)

///////////////////////////////////////////////////////////////////////////////////////////////////

const dbEnabled = true

///////////////////////////////////////////////////////////////////////////////////////////////////

var (
	db                  *bbolt.DB
	dbPath              string
	dbTime              uint64
	persistedStartTime  time.Time
	metaBucketName      = []byte("meta")
	countersBucketName  = []byte("counters")
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

	var err error

	options := &bbolt.Options{
		Timeout:      1 * time.Second,
		FreelistType: bbolt.FreelistMapType,
	}

	db, err = bbolt.Open(dbPath, os.FileMode(dbPerm), options) //nolint:gosec
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
			log.Printf("%sUnclean database shutdown detected!",
				warnPrefix())
		} else {
			t, err := time.Parse(time.RFC3339, string(val))
			if err != nil {
				log.Printf("%sUnable to parse clean shutdown marker date '%s'.",
					warnPrefix(), string(val))
			} else {
				log.Printf("%sDatabase last shutdown %s.",
					dbPrefix(), t.Format("2006-Jan-02 15:04:05"))
			}
		}

		startTimeVal := bucket.Get(initialStartTimeKey)
		if startTimeVal == nil {
			err := bucket.Put(initialStartTimeKey,
				[]byte(startTime.Format(time.RFC3339)))
			if err != nil {
				return err
			}

			persistedStartTime = startTime
		} else {
			pStartTime, err := time.Parse(time.RFC3339, string(startTimeVal))
			if err != nil {
				log.Printf("%sERROR: Failed to parse persisted start time: %v",
					warnPrefix(), err)
				persistedStartTime = startTime
			} else {
				persistedStartTime = pStartTime
			}
		}

		return bucket.Put(shutdownMarkerKey, []byte("0"))
	})
	if err != nil {
		log.Printf("%sERROR: Failed to initialize database metadata: %v",
			errorPrefix(), err)
	}
	loadCountersFromDB()
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func writeCountersToDB() {
	if db == nil {
		return
	}
	err := db.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(countersBucketName)
		if err != nil {
			return err
		}

		counters := map[string]uint64{
			"telnetConnectionsTotal":   lifetimeTelnetConnectionsTotal.Load() + telnetConnectionsTotal.Load(),
			"altHostRoutesTotal":       lifetimeAltHostRoutesTotal.Load() + altHostRoutesTotal.Load(),
			"telnetFailuresTotal":      lifetimeTelnetFailuresTotal.Load() + telnetFailuresTotal.Load(),
			"peakUsersTotal":           lifetimePeakUsersTotal.Load(),
			"trafficOutTotal":          lifetimeTrafficOutTotal.Load() + trafficOutTotal.Load(),
			"trafficInTotal":           lifetimeTrafficInTotal.Load() + trafficInTotal.Load(),
			"sshConnectionsTotal":      lifetimeSSHconnectionsTotal.Load() + sshConnectionsTotal.Load(),
			"sshSessionsTotal":         lifetimeSSHsessionsTotal.Load() + sshSessionsTotal.Load(),
			"monitorSessionsTotal":     lifetimeMonitorSessionsTotal.Load() + monitorSessionsTotal.Load(),
			"sshRequestTimeoutTotal":   lifetimeSSHrequestTimeoutTotal.Load() + sshRequestTimeoutTotal.Load(),
			"sshIllegalSubsystemTotal": lifetimeSSHillegalSubsystemTotal.Load() + sshIllegalSubsystemTotal.Load(),
			"sshExecRejectedTotal":     lifetimeSSHexecRejectedTotal.Load() + sshExecRejectedTotal.Load(),
			"acceptErrorsTotal":        lifetimeAcceptErrorsTotal.Load() + acceptErrorsTotal.Load(),
			"sshHandshakeFailedTotal":  lifetimeSSHhandshakeFailedTotal.Load() + sshHandshakeFailedTotal.Load(),
			"adminKillsTotal":          lifetimeAdminKillsTotal.Load() + adminKillsTotal.Load(),
			"idleKillsTotal":           lifetimeIdleKillsTotal.Load() + idleKillsTotal.Load(),
			"timeKillsTotal":           lifetimeTimeKillsTotal.Load() + timeKillsTotal.Load(),
			"delayAbandonedTotal":      lifetimeDelayAbandonedTotal.Load() + delayAbandonedTotal.Load(),
			"rejectedTotal":            lifetimeRejectedTotal.Load() + rejectedTotal.Load(),
			"exemptedTotal":            lifetimeExemptedTotal.Load() + exemptedTotal.Load(),
		}

		for key, val := range counters {
			buf := make([]byte, 8)
			binary.BigEndian.PutUint64(buf, val)
			err := bucket.Put([]byte(key), buf)
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		log.Printf("%sERROR: Failed to write counters to database: %v",
			errorPrefix(), err)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func loadCountersFromDB() {
	if db == nil {
		return
	}
	err := db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(countersBucketName)
		if bucket == nil {
			return nil
		}

		counters := map[string]*atomic.Uint64{
			"telnetConnectionsTotal":   &lifetimeTelnetConnectionsTotal,
			"altHostRoutesTotal":       &lifetimeAltHostRoutesTotal,
			"telnetFailuresTotal":      &lifetimeTelnetFailuresTotal,
			"peakUsersTotal":           &lifetimePeakUsersTotal,
			"trafficOutTotal":          &lifetimeTrafficOutTotal,
			"trafficInTotal":           &lifetimeTrafficInTotal,
			"sshConnectionsTotal":      &lifetimeSSHconnectionsTotal,
			"sshSessionsTotal":         &lifetimeSSHsessionsTotal,
			"monitorSessionsTotal":     &lifetimeMonitorSessionsTotal,
			"sshRequestTimeoutTotal":   &lifetimeSSHrequestTimeoutTotal,
			"sshIllegalSubsystemTotal": &lifetimeSSHillegalSubsystemTotal,
			"sshExecRejectedTotal":     &lifetimeSSHexecRejectedTotal,
			"acceptErrorsTotal":        &lifetimeAcceptErrorsTotal,
			"sshHandshakeFailedTotal":  &lifetimeSSHhandshakeFailedTotal,
			"adminKillsTotal":          &lifetimeAdminKillsTotal,
			"idleKillsTotal":           &lifetimeIdleKillsTotal,
			"timeKillsTotal":           &lifetimeTimeKillsTotal,
			"delayAbandonedTotal":      &lifetimeDelayAbandonedTotal,
			"rejectedTotal":            &lifetimeRejectedTotal,
			"exemptedTotal":            &lifetimeExemptedTotal,
		}

		for key, val := range counters {
			data := bucket.Get([]byte(key))
			if len(data) == 8 {
				val.Store(binary.BigEndian.Uint64(data))
			}
		}

		return nil
	})
	if err != nil {
		log.Printf("%sERROR: Failed to load counters from database: %v",
			errorPrefix(), err)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func closeDB() {
	if db != nil {
		writeCountersToDB()
		err := db.Update(func(tx *bbolt.Tx) error {
			bucket, err := tx.CreateBucketIfNotExists(metaBucketName)
			if err != nil {
				return err
			}

			return bucket.Put(shutdownMarkerKey, []byte(time.Now().Format(time.RFC3339)))
		})
		if err != nil {
			log.Printf("%sERROR: Failed to set clean shutdown marker: %v",
				errorPrefix(), err)
		}

		err = db.Close()
		if err != nil {
			log.Printf("%sERROR: Failed to close statistics database: %v",
				errorPrefix(), err)
		} else {
			log.Printf("%sStatistics database closed.",
				dbPrefix())
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// vim: set ft=go noexpandtab tabstop=4 cc=100 :
///////////////////////////////////////////////////////////////////////////////////////////////////
