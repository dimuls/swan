package classifier

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	classifierEntity "github.com/dimuls/classifier/entity"

	"github.com/dimuls/swan/entity"
)

type Client struct {
	apiURI     string
	httpClient *http.Client
}

func NewClient(apiURI string) *Client {
	return &Client{apiURI: apiURI, httpClient: &http.Client{}}
}

const (
	trainPath    = "/train"
	trainingPath = "/training"
	classifyPath = "/classify"
)

func (c *Client) Train(samples []entity.CategorySample) error {

	var docs []classifierEntity.Document

	for _, s := range samples {
		docs = append(docs, classifierEntity.Document{
			Text:  s.Text,
			Class: strconv.Itoa(s.CategoryID),
		})
	}

	docsJSON, err := json.Marshal(docs)
	if err != nil {
		return errors.New("failed to JSON marshal docs: " + err.Error())
	}

	res, err := c.httpClient.Post(c.apiURI+trainPath,
		"application/json", bytes.NewReader(docsJSON))
	if err != nil {
		return errors.New("failed to HTTP post: " + err.Error())
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusAccepted {
		return errors.New("not accepted status code")
	}

	return nil
}

func (c *Client) Training() (bool, error) {

	res, err := c.httpClient.Get(c.apiURI + trainingPath)
	if err != nil {
		return false, errors.New("failed to HTTP get from API: " + err.Error())
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return false, errors.New("not OK status code")
	}

	var training bool

	err = json.NewDecoder(res.Body).Decode(&training)
	if err != nil {
		return false, errors.New("failed to decode response body: " +
			err.Error())
	}

	return training, nil
}

func (c *Client) Classify(text string) (int, error) {

	var doc struct {
		Text string
	}

	doc.Text = text

	docJSON, err := json.Marshal(doc)
	if err != nil {
		return 0, errors.New("failed to JSON marshal doc: " + err.Error())
	}

	res, err := c.httpClient.Post(c.apiURI+classifyPath,
		"application/json", bytes.NewReader(docJSON))
	if err != nil {
		return 0, errors.New("failed to HTTP post: " + err.Error())
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusAccepted {
		return 0, errors.New("not accepted status code")
	}

	var class string

	err = json.NewDecoder(res.Body).Decode(&class)
	if err != nil {
		return 0, errors.New("failed to decode response body: " + err.Error())
	}

	categoryID, err := strconv.Atoi(class)
	if err != nil {
		return 0, errors.New("failed to parse category ID: " + err.Error())
	}

	return categoryID, nil
}
