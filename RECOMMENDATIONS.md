# Trusted Setup Best Practices

## Running the Ceremony

Participants of the ceremony sample some randomness, perform a computation, and then destroy the randomness. **Only one participant needs to do this successfully to ensure the final parameters are secure.** In order to see that this randomness is truly destroyed, participants may take various kinds of precautions:

* putting the machine in a Faraday cage
* destroying the machine afterwards
* running the software on secure hardware
* not connecting the hardware to any networks
* using multiple machines and randomly picking the result of one of them to use
* using different code than what we have provided
* using a secure operating system
* using an operating system that nobody would expect you to use (Rust can compile to Mac OS X and Windows)
* using an unusual Rust toolchain or [alternate rust compiler](https://github.com/thepowersgang/mrustc)
* lots of other ideas we can't think of

It is totally up to the participants. In general, participants should be aware of side-channel attacks and assume that remnants of the randomness will be in RAM after the computation has finished.

(the above section is taken from the [original powersoftau](https://github.com/ebfull/powersoftau) repository)

## Verifying execution of Powers of Tau

When contributing, Powers of Tau outputs the accumulator's hash to your terminal. This should be made available to the next contributor separately, as a checksum so that they can verify the file they have received is not tampered with.

As a final step, a randomness beacon is applied to the ceremony by the coordinator. This can be verified by running [this software](https://github.com/plutomonkey/verify-beacon/).
