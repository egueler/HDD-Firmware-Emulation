# HDD-Firmware-Emulation
Back in 2018, I had this idea to build an emulator for HDD or SSD firmware so I can hunt for security vulnerabilities via fuzzing. There was barely any research or articles on firmware fuzzing back in the day, now there is plently. One of the ideas was to find vulnerabilities in regards to the caching mechanism, e.g., would a user be able to corrupt the cache somehow and use it to escalate her privileges?  

This script is the hacky byproduct of that effort, it's able to run the Samsung HM641JI HDD firmware right up to the main loop using Unicorn. Never actually came around to implement the fuzzing portion of it. Might still be helpful to some.
