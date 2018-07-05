#!/bin/bash
# Basic while loop
run_amount=20
counter=1
while [ $counter -le $run_amount ]
do
echo "******* RUNNING DEMO. ATTEMPT $counter **********"
./demo
((counter++))
done
echo All done
