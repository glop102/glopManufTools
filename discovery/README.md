# Discovery Service

This is a standalone process that is able to leverage different scanners on individual interfaces to find computers or other hardware.
Clients of this service will have a convenient connect() method available that will transparently spawn the new discovery process if it is not already running.
All IPC is done via sockets with null byte seperated messages encoded as json.

Managment interface
- Clients connect and can query
  - All cached discoveries, or discoveries within a time period
  - currently running scanners amd available scanners -> mapping of scanner_type to list\[interfaces\]
- Clients can send commands
  - single time no exit whith no clients -> any client connecting clears the flag and will exit with no clients again
  - flush all cache and have all hardware told that it has gone offline to all clients
  - Turn scanners on/off per interface
  - elevate the socket spawner preemptivly

Dream list
- widget in the corner as a client that can do some etra controls and keep discovery running between main program sessions and maybe just be a handy thing to eyeball what is around