package main

import (
	"sync"
)

type action func() error

func performConcurrentActions(actions ...action) []error {
	if len(actions) == 0 {
		return nil
	}
	var wg sync.WaitGroup
	errChan := make(chan error, len(actions))

	wg.Add(len(actions))

	for _, act := range actions {
		go func(act action) {
			defer wg.Done()
			if err := act(); err != nil {
				errChan <- err
			}
		}(act)
	}

	wg.Wait()
	close(errChan)

	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}

	return errs
}
