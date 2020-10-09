
# coding: utf-8
from __future__ import absolute_import

import os, bz2, gzip
from . import dpkt, mrt, bgp


## reference code: https://jon.oberheide.org/pybgpdump/
##
## compressed data format:
##  RouteView.org : *.bz2, ref: http://archive.routeviews.org/
##  RIPE NCC RIS  : *.gz,  ref: https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris/ris-raw-data

class _BGPDumpBase(object):

  def __init__(self, filename):
    f = open(filename, 'rb')
    hdr = f.read(len(self.MAGIC))
    f.close()

    assert os.path.isfile(filename) and hdr.startswith(self.MAGIC), \
      'Invalid filename <{}>'.format(filename)

    self.f = self.COMPRESSION_CLASS(filename, 'rb')

  def close(self):
    self.f.close()

  def records(self):

    while True:

      mrt_h, bgp_h, bgp_m = None, None, None

      buf = self.f.read(self.MRT_HEADER_LEN)
      if len(buf) < self.MRT_HEADER_LEN:
        self.close()
        break

      mrt_h = mrt.MRTHeader(buf)

      len_read = mrt_h.len
      if mrt_h.type in (mrt.BGP4MP_ET, ):
        buf += self.f.read(4)
        len_read -= 4
        mrt_h = mrt.MRTHeader_ET(buf)

      buf = self.f.read(len_read)
      if len(buf) < len_read:
        self.close()
        break

      if mrt_h.subtype == mrt.BGP4MP_MESSAGE:
        bgp_h = mrt.BGP4MPMessage(buf)
      elif mrt_h.subtype == mrt.BGP4MP_MESSAGE_32BIT_AS:
        bgp_h = mrt.BGP4MPMessage_32(buf)
      else:
        continue

      bgp_m = bgp.BGP(bgp_h.data)
      bgp_h.data = bgp_h.bgp  = bgp_m
      mrt_h.bgp4mp = mrt_h.data = bgp_h

      yield mrt_h

    return

class BGPDumpBZ2(_BGPDumpBase):

  MAGIC = b'\x42\x5a\x68'
  MRT_HEADER_LEN    = mrt.MRTHeader.__hdr_len__
  COMPRESSION_CLASS = bz2.BZ2File

  def __init__(self, filename):
    super(BGPDumpBZ2, self).__init__(filename)



class BGPDumpGZ(_BGPDumpBase):

  MAGIC = b'\x1f\x8b'
  MRT_HEADER_LEN = mrt.MRTHeader.__hdr_len__
  COMPRESSION_CLASS = gzip.GzipFile

  def __init__(self, filename):
    super(BGPDumpGZ, self).__init__(filename)


