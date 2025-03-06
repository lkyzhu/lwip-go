package main

import (
	"github.com/lkyzhu/lwip-go/netif"
	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
)

func NewDriver(name string) (netif.Driver, error) {
	cfg := water.Config{
		DeviceType: water.TUN,
	}
	cfg.Name = name
	cfg.Persist = true
	tunDev, err := water.New(cfg)
	if err != nil {
		logrus.WithError(err).Errorf("new tun device fail")
		return nil, err
	}

	dr := &driver{
		dev: tunDev,
	}
	logrus.Infof("new driver:%v, success\n", dr.dev.Name())
	return dr, nil
}

type driver struct {
	dev *water.Interface
}

func (self *driver) Input(buff []byte) (int, error) {
	return 0, nil
}

func (self *driver) Output(data []byte) (int, error) {
	return self.dev.Write(data)
}

func (self *driver) Write([]byte) (int, error) {
	return 0, nil
}

func (self *driver) Read(buff []byte) (int, error) {
	return self.dev.Read(buff)
}
