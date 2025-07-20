package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type JobStatus string

const (
	PendingStatus   JobStatus = "pending"
	ProcessingStatus JobStatus = "processing"
	CompletedStatus  JobStatus = "completed"
	FailedStatus     JobStatus = "failed"
	RetryStatus      JobStatus = "retry"
)

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

type JobQueue struct {
	client *redis.Client
	queues map[string]*Queue
}

func NewJobQueue(client *redis.Client) *JobQueue {
	return &JobQueue{
		client: client,
		queues: make(map[string]*Queue),
	}
}

type Queue struct {
	name   string
	client *redis.Client
}

func (jq *JobQueue) NewQueue(name string) *Queue {
	queue := &Queue{
		name:   name,
		client: jq.client,
	}
	jq.queues[name] = queue
	return queue
}

func (q *Queue) Enqueue(ctx context.Context, job *Job) error {
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
	
	data, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("failed to marshal job: %w", err)
	}
	
	score := float64(job.CreatedAt.Unix())
	if job.Delay > 0 {
		score = float64(job.CreatedAt.Add(job.Delay).Unix())
	}
	
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

func (q *Queue) Dequeue(ctx context.Context) (*Job, error) {
	key := fmt.Sprintf("queue:%s", q.name)
	
	result, err := q.client.ZRangeWithScores(ctx, key, 0, 0).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to dequeue job: %w", err)
	}
	
	if len(result) == 0 {
		return nil, nil // No jobs available
	}
	
	jobData := result[0].Member.(string)
	score := result[0].Score
	
	if score > float64(time.Now().Unix()) {
		return nil, nil // Job is still delayed
	}
	
	err = q.client.ZRem(ctx, key, jobData).Err()
	if err != nil {
		return nil, fmt.Errorf("failed to remove job from queue: %w", err)
	}
	
	var job Job
	err = json.Unmarshal([]byte(jobData), &job)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal job: %w", err)
	}
	
	job.Status = ProcessingStatus
	now := time.Now()
	job.ProcessedAt = &now
	
	return &job, nil
}

func (q *Queue) GetJob(ctx context.Context, jobID string) (*Job, error) {
	key := fmt.Sprintf("queue:%s", q.name)
	
	jobs, err := q.client.ZRange(ctx, key, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get jobs: %w", err)
	}
	
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

func (q *Queue) UpdateJob(ctx context.Context, job *Job) error {
	err := q.RemoveJob(ctx, job.ID)
	if err != nil {
		return fmt.Errorf("failed to remove old job: %w", err)
	}
	
	return q.Enqueue(ctx, job)
}

func (q *Queue) RemoveJob(ctx context.Context, jobID string) error {
	key := fmt.Sprintf("queue:%s", q.name)
	
	jobs, err := q.client.ZRange(ctx, key, 0, -1).Result()
	if err != nil {
		return fmt.Errorf("failed to get jobs: %w", err)
	}
	
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

func (q *Queue) GetQueueStats(ctx context.Context) (map[string]interface{}, error) {
	key := fmt.Sprintf("queue:%s", q.name)
	
	size, err := q.client.ZCard(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get queue size: %w", err)
	}
	
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

type JobProcessor struct {
	queue     *Queue
	handlers  map[string]JobHandler
	workers   int
	stopChan  chan struct{}
}

type JobHandler func(ctx context.Context, job *Job) error

func NewJobProcessor(queue *Queue, workers int) *JobProcessor {
	return &JobProcessor{
		queue:    queue,
		handlers: make(map[string]JobHandler),
		workers:  workers,
		stopChan: make(chan struct{}),
	}
}

func (jp *JobProcessor) RegisterHandler(jobType string, handler JobHandler) {
	jp.handlers[jobType] = handler
}

func (jp *JobProcessor) Start(ctx context.Context) {
	for i := 0; i < jp.workers; i++ {
		go jp.worker(ctx, i)
	}
}

func (jp *JobProcessor) Stop() {
	close(jp.stopChan)
}

func (jp *JobProcessor) worker(ctx context.Context, workerID int) {
	for {
		select {
		case <-jp.stopChan:
			return
		default:
			job, err := jp.queue.Dequeue(ctx)
			if err != nil {
				time.Sleep(time.Second)
				continue
			}
			
			if job == nil {
				time.Sleep(time.Second)
				continue
			}
			
			jp.processJob(ctx, job)
		}
	}
}

func (jp *JobProcessor) processJob(ctx context.Context, job *Job) {
	handler, exists := jp.handlers[job.Type]
	if !exists {
		job.Status = FailedStatus
		job.Error = fmt.Sprintf("no handler for job type: %s", job.Type)
		jp.queue.Enqueue(ctx, job)
		return
	}
	
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
			job.Delay = time.Duration(job.RetryCount) * time.Minute
		}
	} else {
		job.Status = CompletedStatus
		now := time.Now()
		job.CompletedAt = &now
	}
	
	jp.queue.Enqueue(ctx, job)
}

func generateJobID() string {
	return fmt.Sprintf("job_%d", time.Now().UnixNano())
}

type JobQueueHandler struct {
	jobQueue *JobQueue
}

func NewJobQueueHandler(jobQueue *JobQueue) *JobQueueHandler {
	return &JobQueueHandler{jobQueue: jobQueue}
}

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
