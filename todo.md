
# TODO

## High Priority
- [ ] amr conditionals
- [ ] instruction injection vs data injection and trustlevels

## In Progress
- [ ] Define precisely how to tackle insturction vs data injections

## Backlog
- [ ] Measure utility drop between different restrictive vocabulary levels of AMR parsing
- [ ] Think about the implementation of variables, user defines variables, tools can not overwrite the userdefined iban for example

## Done
- [x] Simplify agentdojo such to the simpelest case and verify the firewall is working
- [x] define what agentdojo should do
- [x] define what the firewall should do -> gain clarity
- [x] build simple custom tasks
- [x] build first agentdojo pipeline
- [x] Get an overview of agentdojo
- [x] Implement firewall prototype



CaMeL paper, Defeating prompt injection by design
measurability
differential testing, raw or amr

larger set of test cases, (use claude)
track utility metrics raw amr, (implemented but needs testing, has a global boolean flag in config)
check amr similarity tools (maybe it helps to know when graphs are similar so look into 3rd party tools again and if we could use them)