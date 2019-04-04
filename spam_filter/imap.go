package spam_filter

import (
	"fmt"
	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
)

type Server struct {
	Username string
	Password string
	Server   string
	Port     int

	client *client.Client
}

func (s *Server) Login() error {

	c, err := client.DialTLS(fmt.Sprintf("%s:%d", s.Server, s.Port), nil)
	if err != nil {
		return err
	}
	s.client = c

	if err := s.client.Login(s.Username, s.Password); err != nil {
		return err
	}

	return nil
}

func (s *Server) Logout() error {
	return s.client.Logout()
}

func (s *Server) GetMessageUIDS(mailbox string) (uids []uint32, err error) {

	mbox, err := s.client.Select(mailbox, false)
	if err != nil {
		return nil, err
	}

	set := &imap.SeqSet{}
	set.AddRange(1, mbox.Messages)

	done := make(chan error, 1)
	messageChan := make(chan *imap.Message, len(set.Set))
	go func() {
		done <- s.client.Fetch(set, []imap.FetchItem{imap.FetchUid}, messageChan)
	}()

	for msg := range messageChan {
		uids = append(uids, msg.Uid)
	}

	if err := <-done; err != nil {
		return nil, err
	}

	return uids, nil
}

func (s *Server) GetMessageEnvelope(mailbox string, uids []uint32) (msgs []*imap.Message, err error) {

	_, err = s.client.Select(mailbox, false)
	if err != nil {
		return nil, err
	}

	set := &imap.SeqSet{}
	set.AddNum(uids...)

	done := make(chan error, 1)
	messageChan := make(chan *imap.Message, len(set.Set))
	go func() {
		done <- s.client.UidFetch(set, []imap.FetchItem{imap.FetchEnvelope, imap.FetchUid}, messageChan)
	}()

	for m := range messageChan {
		msgs = append(msgs, m)
	}

	if err := <-done; err != nil {
		return nil, err
	}

	return msgs, nil
}

func (s *Server) GetMessage(mailbox string, uids []uint32) (msgs []*imap.Message, err error) {

	_, err = s.client.Select(mailbox, false)
	if err != nil {
		return nil, err
	}

	set := &imap.SeqSet{}
	set.AddNum(uids...)

	done := make(chan error, 1)
	messageChan := make(chan *imap.Message, len(set.Set))
	go func() {
		done <- s.client.UidFetch(set, []imap.FetchItem{imap.FetchRFC822, imap.FetchUid}, messageChan)
	}()

	for m := range messageChan {
		msgs = append(msgs, m)
	}

	if err := <-done; err != nil {
		return nil, err
	}

	return msgs, nil
}
