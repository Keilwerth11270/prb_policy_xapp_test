# PRB Policy Sending xApp

Clone of Dr. Alexandre Huff's Bouncer xApp (test branch) where he waits for policies to be sent via A1 and repackages them according to E2SM  and forwards them to any associated gNBs via E2. I cut out the need for a Non-RT-RIC/Policy being sent via the A1 and instead hardcoded a policy to be sent to any associated gNB(s) in 30 second intervals. 

# Bouncer xApp

The purpose of this repository is to maintain a local implementation of the bouncer xapp implementing the E2SM-RC and E2SM-KPM service models. This repository "mirrors" the official source code from the O-RAN SC bouncer repository.

Maintainer: Alexandre Huff <<alexandrehuff@utfpr.edu.br>>

