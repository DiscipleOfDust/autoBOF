#!gdb
import sys
import gdb
import os
os.system("echo resetFile > eip.txt")
number_restarts = 100
gdb.execute("set pagination off")
os.system("/usr/share/metasploit-framework/vendor/bundle/ruby/2.3.0/gems/rex-bin_tools-0.1.4/bin/msfelfscan -j esp ./crossfire > jmpSearch.txt")
def on_stop(sig):
  global number_restarts
  if isinstance(sig, gdb.SignalEvent):
    if (number_restarts > 0):
      os.system("rm eip.txt")
      gdb.execute("set confirm off")
      gdb.execute("set logging file eip.txt")
      gdb.execute("set logging on")
      gdb.execute("set logging overwrite on")
      gdb.execute("info registers eip")
      gdb.execute("set logging off")
      gdb.execute("set logging file badchars.txt")
      gdb.execute("set logging on")
      gdb.execute("x/500xw $esp")
      gdb.execute("set logging overwrite off")
      gdb.execute("set logging off")
      gdb.execute("kill")
      gdb.execute("run")
gdb.events.stop.connect (on_stop)
gdb.execute("run")
