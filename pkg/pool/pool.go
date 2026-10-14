// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package pool

import (
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var logger = Logger(log.New(os.Stderr, "[pool]", log.Ldate|log.Ltime))

type Logger interface {
	Println(...interface{})
	Printf(string, ...interface{})
}

// createWorker wraps a task function into a worker
type Worker struct {
	f func(interface{})
}

// generateWorker creates a worker for f
func generateWorker(f func(interface{})) *Worker {
	return &Worker{f: f}
}

// run executes the worker
func (t *Worker) run(in interface{}) {
	t.f(in)
}

// Pool is a bounded worker pool
type Pool struct {
	// task function
	Function func(interface{})
	// input queue
	in chan interface{}
	// number of workers; never exceeded
	threads int
	// delay between spawning workers
	Interval time.Duration
	// number of busy workers
	length int32
	// blocks until all workers exit
	wg *sync.WaitGroup
	// early-stop flag
	Done atomic.Bool
}

// New creates a worker pool with the given size
func New(threads int) *Pool {
	return &Pool{
		threads:  threads,
		wg:       &sync.WaitGroup{},
		in:       make(chan interface{}),
		Function: nil,
		Interval: time.Duration(0),
	}
}

// Push enqueues a job; it is dropped if the pool already stopped.
func (p *Pool) Push(i interface{}) {
	if p.Done.Load() {
		return
	}
	defer func() {
		if e := recover(); e != nil {
			logger.Println("pool.Push panic (channel closed before Push):", e)
		}
	}()
	p.in <- i
}

// Stop closes the input queue once.
func (p *Pool) Stop() {
	if p.Done.CompareAndSwap(false, true) {
		close(p.in)
	}
}

// Run starts the workers and blocks until the queue drains
func (p *Pool) Run() {
	p.Done.Store(false)
	// Spawn at most p.threads workers to bound resource usage
	for i := 0; i < p.threads; i++ {
		p.wg.Add(1)
		time.Sleep(p.Interval)
		go p.work()
		if p.Done.Load() {
			break
		}
	}
	p.wg.Wait()
}

// work consumes jobs until the input channel is closed.
func (p *Pool) work() {
	// decrement the wait group on exit
	defer p.wg.Done()
	for param := range p.in {
		// An already-dequeued job must run: Stop() may have flipped Done by now, and exiting
		// here would silently drop it while the phase stats read as complete.
		atomic.AddInt32(&p.length, 1)
		p.runJob(param)
		atomic.AddInt32(&p.length, -1)
	}
}

// runJob executes one job and contains its panic - one bad job must not kill the whole
// process; length is decremented by the caller after runJob returns (panic is caught here).
func (p *Pool) runJob(param interface{}) {
	defer func() {
		if e := recover(); e != nil {
			logger.Println(param, e)
		}
	}()
	// set the task function
	f := generateWorker(p.Function)
	// run the job
	f.run(param)
}

// RunningThreads returns the number of busy workers
func (p *Pool) RunningThreads() int {
	return int(atomic.LoadInt32(&p.length))
}
