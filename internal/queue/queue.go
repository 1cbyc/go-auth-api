package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// JobStatus represents the status of a job
type JobStatus string

const (
	PendingStatus   JobStatus = "pending"
	ProcessingStatus JobStatus = "processing"
	CompletedStatus  JobStatus = "completed"
	FailedStatus     JobStatus = "failed"
	RetryStatus      JobStatus = "retry"
)

// Job represents a job in the queue
type Job struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Data        map[string]interface{} `json:"data"`
	Status      JobStatus              `json:"status"`
	Priority    int                    `json:"priority"`
	RetryCount  int                    `json:"retry_count"`
	MaxRetries  int                    `json:"max_retries"`
	CreatedAt   time.Time              `json:"created_at"`
	ProcessedAt *time.Time             `json:"processed_at,omitempty"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Delay       time.Duration          `json:"delay,omitempty"`
}

// JobQueue represents a job queue
type JobQueue struct {
	client *redis.Client
	queues map[string]*Queue
}

// NewJobQueue creates a new job queue
func NewJobQueue(client *redis.Client) *JobQueue {
	return &JobQueue{
		client: client,
		queues: make(map[string]*Queue),
	}
}

// Queue represents a specific queue
type Queue struct {
	name   string
	client *redis.Client
}

// NewQueue creates a new queue
func (jq *JobQueue) NewQueue(name string) *Queue {
	queue := &Queue{
		name:   name,
		client: jq.client,
	}
	jq.queues[name] = queue
	return queue
}

// Enqueue adds a job to the queue
func (q *Queue) Enqueue(ctx context.Context, job *Job) error {
	// Set default values
	if job.ID == "" {
		job.ID = generateJobID()
	}
	if job.CreatedAt.IsZero() {
		job.CreatedAt = time.Now()
	}
	if job.MaxRetries == 0 {
		job.MaxRetries = 3
	}
	if job.Priority == 0 {
		job.Priority = 5 // Default priority
	}
	
	// Marshal job
	data, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("failed to marshal job: %w", err)
	}
	
	// Calculate score for priority queue
	score := float64(job.CreatedAt.Unix())
	if job.Delay > 0 {
		score = float64(job.CreatedAt.Add(job.Delay).Unix())
	}
	
	// Add to Redis sorted set
	key := fmt.Sprintf("queue:%s", q.name)
	err = q.client.ZAdd(ctx, key, redis.Z{
		Score:  score,
		Member: data,
	}).Err()
	
	if err != nil {
		return fmt.Errorf("failed to enqueue job: %w", err)
	}
	
	return nil
}

// Dequeue retrieves and removes the next job from the queue
func (q *Queue) Dequeue(ctx context.Context) (*Job, error) {
	key := fmt.Sprintf("queue:%s", q.name)
	
	// Get job with lowest score (highest priority, earliest time)
	result, err := q.client.ZRangeWithScores(ctx, key, 0, 0).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to dequeue job: %w", err)
	}
	
	if len(result) == 0 {
		return nil, nil // No jobs available
	}
	
	// Check if job is ready to be processed (delay has passed)
	jobData := result[0].Member.(string)
	score := result[0].Score
	
	if score > float64(time.Now().Unix()) {
		return nil, nil // Job is still delayed
	}
	
	// Remove job from queue
	err = q.client.ZRem(ctx, key, jobData).Err()
	if err != nil {
		return nil, fmt.Errorf("failed to remove job from queue: %w", err)
	}
	
	// Unmarshal job
	var job Job
	err = json.Unmarshal([]byte(jobData), &job)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal job: %w", err)
	}
	
	// Update job status
	job.Status = ProcessingStatus
	now := time.Now()
	job.ProcessedAt = &now
	
	return &job, nil
}

// GetJob retrieves a job by ID
func (q *Queue) GetJob(ctx context.Context, jobID string) (*Job, error) {
	key := fmt.Sprintf("queue:%s", q.name)
	
	// Get all jobs
	jobs, err := q.client.ZRange(ctx, key, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get jobs: %w", err)
	}
	
	// Find job by ID
	for _, jobData := range jobs {
		var job Job
		err := json.Unmarshal([]byte(jobData), &job)
		if err != nil {
			continue
		}
		
		if job.ID == jobID {
			return &job, nil
		}
	}
	
	return nil, fmt.Errorf("job not found")
}

// UpdateJob updates a job in the queue
func (q *Queue) UpdateJob(ctx context.Context, job *Job) error {
	// Remove old job
	err := q.RemoveJob(ctx, job.ID)
	if err != nil {
		return fmt.Errorf("failed to remove old job: %w", err)
	}
	
	// Add updated job
	return q.Enqueue(ctx, job)
}

// RemoveJob removes a job from the queue
func (q *Queue) RemoveJob(ctx context.Context, jobID string) error {
	key := fmt.Sprintf("queue:%s", q.name)
	
	// Get all jobs
	jobs, err := q.client.ZRange(ctx, key, 0, -1).Result()
	if err != nil {
		return fmt.Errorf("failed to get jobs: %w", err)
	}
	
	// Find and remove job by ID
	for _, jobData := range jobs {
		var job Job
		err := json.Unmarshal([]byte(jobData), &job)
		if err != nil {
			continue
		}
		
		if job.ID == jobID {
			err = q.client.ZRem(ctx, key, jobData).Err()
			if err != nil {
				return fmt.Errorf("failed to remove job: %w", err)
			}
			return nil
		}
	}
	
	return fmt.Errorf("job not found")
}

// GetQueueStats returns statistics about the queue
func (q *Queue) GetQueueStats(ctx context.Context) (map[string]interface{}, error) {
	key := fmt.Sprintf("queue:%s", q.name)
	
	// Get queue size
	size, err := q.client.ZCard(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get queue size: %w", err)
	}
	
	// Get jobs by status
	jobs, err := q.client.ZRange(ctx, key, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get jobs: %w", err)
	}
	
	statusCounts := make(map[JobStatus]int)
	for _, jobData := range jobs {
		var job Job
		err := json.Unmarshal([]byte(jobData), &job)
		if err != nil {
			continue
		}
		statusCounts[job.Status]++
	}
	
	return map[string]interface{}{
		"queue_name":    q.name,
		"total_jobs":    size,
		"pending":       statusCounts[PendingStatus],
		"processing":    statusCounts[ProcessingStatus],
		"completed":     statusCounts[CompletedStatus],
		"failed":        statusCounts[FailedStatus],
		"retry":         statusCounts[RetryStatus],
	}, nil
}

// JobProcessor represents a job processor
type JobProcessor struct {
	queue     *Queue
	handlers  map[string]JobHandler
	workers   int
	stopChan  chan struct{}
}

// JobHandler represents a job handler function
type JobHandler func(ctx context.Context, job *Job) error

// NewJobProcessor creates a new job processor
func NewJobProcessor(queue *Queue, workers int) *JobProcessor {
	return &JobProcessor{
		queue:    queue,
		handlers: make(map[string]JobHandler),
		workers:  workers,
		stopChan: make(chan struct{}),
	}
}

// RegisterHandler registers a job handler
func (jp *JobProcessor) RegisterHandler(jobType string, handler JobHandler) {
	jp.handlers[jobType] = handler
}

// Start starts the job processor
func (jp *JobProcessor) Start(ctx context.Context) {
	for i := 0; i < jp.workers; i++ {
		go jp.worker(ctx, i)
	}
}

// Stop stops the job processor
func (jp *JobProcessor) Stop() {
	close(jp.stopChan)
}

// worker processes jobs
func (jp *JobProcessor) worker(ctx context.Context, workerID int) {
	for {
		select {
		case <-jp.stopChan:
			return
		default:
			// Dequeue job
			job, err := jp.queue.Dequeue(ctx)
			if err != nil {
				time.Sleep(time.Second)
				continue
			}
			
			if job == nil {
				time.Sleep(time.Second)
				continue
			}
			
			// Process job
			jp.processJob(ctx, job)
		}
	}
}

// processJob processes a single job
func (jp *JobProcessor) processJob(ctx context.Context, job *Job) {
	// Get handler
	handler, exists := jp.handlers[job.Type]
	if !exists {
		job.Status = FailedStatus
		job.Error = fmt.Sprintf("no handler for job type: %s", job.Type)
		jp.queue.Enqueue(ctx, job)
		return
	}
	
	// Execute handler
	err := handler(ctx, job)
	if err != nil {
		job.RetryCount++
		job.Error = err.Error()
		
		if job.RetryCount >= job.MaxRetries {
			job.Status = FailedStatus
			now := time.Now()
			job.CompletedAt = &now
		} else {
			job.Status = RetryStatus
			// Add delay for retry
			job.Delay = time.Duration(job.RetryCount) * time.Minute
		}
	} else {
		job.Status = CompletedStatus
		now := time.Now()
		job.CompletedAt = &now
	}
	
	// Update job in queue
	jp.queue.Enqueue(ctx, job)
}

// generateJobID generates a unique job ID
func generateJobID() string {
	return fmt.Sprintf("job_%d", time.Now().UnixNano())
}

// JobQueueHandler handles job queue HTTP requests
type JobQueueHandler struct {
	jobQueue *JobQueue
}

// NewJobQueueHandler creates a new job queue handler
func NewJobQueueHandler(jobQueue *JobQueue) *JobQueueHandler {
	return &JobQueueHandler{jobQueue: jobQueue}
}

// EnqueueJob handles job enqueue requests
func (jqh *JobQueueHandler) EnqueueJob(c *gin.Context) {
	queueName := c.Param("queue")
	queue := jqh.jobQueue.NewQueue(queueName)
	
	var req struct {
		Type     string                 `json:"type" binding:"required"`
		Data     map[string]interface{} `json:"data" binding:"required"`
		Priority int                    `json:"priority,omitempty"`
		Delay    time.Duration          `json:"delay,omitempty"`
		MaxRetries int                  `json:"max_retries,omitempty"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	
	job := &Job{
		Type:       req.Type,
		Data:       req.Data,
		Priority:   req.Priority,
		Delay:      req.Delay,
		MaxRetries: req.MaxRetries,
		Status:     PendingStatus,
	}
	
	err := queue.Enqueue(c.Request.Context(), job)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	
	c.JSON(200, gin.H{
		"message": "Job enqueued successfully",
		"job_id":  job.ID,
	})
}

// GetJobStatus gets the status of a job
func (jqh *JobQueueHandler) GetJobStatus(c *gin.Context) {
	queueName := c.Param("queue")
	jobID := c.Param("job_id")
	
	queue := jqh.jobQueue.NewQueue(queueName)
	job, err := queue.GetJob(c.Request.Context(), jobID)
	if err != nil {
		c.JSON(404, gin.H{"error": "Job not found"})
		return
	}
	
	c.JSON(200, job)
}

// GetQueueStats gets queue statistics
func (jqh *JobQueueHandler) GetQueueStats(c *gin.Context) {
	queueName := c.Param("queue")
	queue := jqh.jobQueue.NewQueue(queueName)
	
	stats, err := queue.GetQueueStats(c.Request.Context())
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	
	c.JSON(200, stats)
} 