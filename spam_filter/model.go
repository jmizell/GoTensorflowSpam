package spam_filter

import (
	tf "github.com/tensorflow/tensorflow/tensorflow/go"
)

type Model struct {
	Input  string
	Output string
	Path string

	m *tf.SavedModel
}

func (m *Model) Load() (err error) {

	m.m, err = tf.LoadSavedModel(m.Path, []string{"serve"}, nil)
	if err != nil {
		return err
	}

	return nil
}

func (m *Model) Classify(input interface{}) ([]*tf.Tensor, error) {

	tensor, err := tf.NewTensor(input)
	if err != nil {
		return nil, err
	}

	feeds := map[tf.Output]*tf.Tensor{
		m.m.Graph.Operation(m.Input).Output(0): tensor,
	}

	fetches := []tf.Output{
		m.m.Graph.Operation(m.Output).Output(0),
	}

	output, err := m.m.Session.Run(feeds, fetches, nil)

	if err != nil {
		return nil, err
	}

	return output, err
}
