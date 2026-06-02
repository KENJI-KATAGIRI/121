#!/bin/bash
sudo systemctl restart bni-manager
sudo systemctl status bni-manager --no-pager | head -10
