module chux0r.org/netbang

go 1.20

require github.com/ns3777k/go-shodan/v4 v4.2.0

require (
	chux0r.org/osutils v0.0.0
	chux0r.org/portfu v0.0.0
	chux0r.org/uglynum v0.0.0
	github.com/Mega0hm/rawsock v0.0.0-20240325170206-816f595ffc9a
	github.com/google/go-querystring v1.0.0 // indirect
)

replace (
	chux0r.org/osutils => ./utils
	chux0r.org/portfu => ./portfu
	chux0r.org/uglynum => ./utils/uglynum
)
