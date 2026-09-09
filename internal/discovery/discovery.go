package discovery

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"
)

type Config struct {
	Ports       []int
	Timeout     time.Duration
	Concurrency int
}

type result struct {
	index int
	alive bool
}

func Discover(
	ctx context.Context,
	hosts []string,
	cfg Config,
) []string {
	if len(hosts) == 0 {
		return nil
	}

	if cfg.Concurrency < 1 {
		cfg.Concurrency = 64
	}

	if cfg.Timeout <= 0 {
		cfg.Timeout = 300 * time.Millisecond
	}

	jobs := make(chan int)
	results := make(chan result)

	workers := cfg.Concurrency

	if workers > len(hosts) {
		workers = len(hosts)
	}

	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for index := range jobs {
				alive := isAlive(
					ctx,
					hosts[index],
					cfg,
				)

				select {
				case results <- result{
					index: index,
					alive: alive,
				}:

				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(jobs)

		for index := range hosts {
			select {
			case jobs <- index:

			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	aliveMap := make(
		[]bool,
		len(hosts),
	)

	for res := range results {
		if res.alive {
			aliveMap[res.index] = true
		}
	}

	var alive []string

	for index, host := range hosts {
		if aliveMap[index] {
			alive = append(
				alive,
				host,
			)
		}
	}

	return alive
}

func isAlive(
	ctx context.Context,
	host string,
	cfg Config,
) bool {
	dialer := net.Dialer{
		Timeout: cfg.Timeout,
	}

	for _, port := range cfg.Ports {
		select {
		case <-ctx.Done():
			return false

		default:
		}

		addr := net.JoinHostPort(
			host,
			strconv.Itoa(port),
		)

		conn, err := dialer.DialContext(
			ctx,
			"tcp",
			addr,
		)

		if err != nil {
			continue
		}

		_ = conn.Close()

		return true
	}

	return false
}
