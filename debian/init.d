#!/bin/sh

### BEGIN INIT INFO
# Provides:		vncauthproxy
# Required-Start:	$remote_fs $syslog $network
# Required-Stop:	$remote_fs $syslog
# Should-Start:		
# Should-Stop:		
# Default-Start:	2 3 4 5
# Default-Stop:		0 1 6
# Short-Description:	VNC authentication proxy
# Description:		VNC authentication proxy
### END INIT INFO

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
DAEMON=/usr/sbin/vncauthproxy
NAME="vncauthproxy"
DESC="VNC authentication proxy"
RUNDIR=/var/run/$NAME
LOGDIR=/var/log/$NAME
PIDFILE=$RUNDIR/$NAME.pid
CHUID="nobody:nogroup"

. /lib/lsb/init-functions

test -x $DAEMON || exit 0

DAEMON_OPTS="--pid-file=$PIDFILE"

# Read configuration variable file if it is present
[ -r /etc/default/$NAME ] && . /etc/default/$NAME

case "$1" in
  start)
	mkdir -p $RUNDIR
	chown $CHUID $RUNDIR $LOGDIR
	chmod 0755 $RUNDIR $LOGDIR

	if pidofproc -p $PIDFILE $DAEMON > /dev/null; then
		log_failure_msg "Starting $DESC (already started)"
		exit 0
	fi
	log_daemon_msg "Starting $DESC" "$NAME"
	start-stop-daemon --start --quiet --pidfile $PIDFILE \
		--chuid $CHUID \
		--exec $DAEMON -- $DAEMON_OPTS
	log_end_msg $?
	;;
  stop)
	log_daemon_msg "Stopping $DESC" "$NAME"
	start-stop-daemon --stop --quiet --pidfile $PIDFILE
	case "$?" in
		0) log_end_msg 0 ;;
		1) log_progress_msg "(already stopped)"
		   log_end_msg 0 ;;
		*) log_end_msg 1 ;;
	esac
	;;
  force-reload|restart)
	$0 stop
	$0 start
	;;
  status)
	status_of_proc -p $PIDFILE $BIN $NAME && exit 0 || exit $?
	;;
  *)
	echo "Usage: ${0} {start|stop|restart|force-reload|status}" >&2
	exit 1
	;;
esac