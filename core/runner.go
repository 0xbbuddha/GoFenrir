package core

import "sync"

// Job represents one unit of work: one target paired with one credential.
type Job struct {
	Target string
	Cred   Credential
}

// RunConcurrent executes fn for each job using at most threads goroutines.
func RunConcurrent(jobs []Job, threads int, fn func(Job)) {
	if threads <= 0 {
		threads = 1
	}

	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, job := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(j Job) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(j)
		}(job)
	}

	wg.Wait()
}
