import atheris

with atheris.instrument_imports():
    import sys
    import random

# Create random numbers to create minor fuzzing complexity
rLow = random.randint(1,100)
rHigh = random.randint(rLow+1,rLow*1024)
r1 = random.randint(rLow, rHigh)

# This is where the fuzzer begins
def EntryPoint(input_data):
    
    # var "input_data" is a series of bytes that the fuzzer is manipulating 
    # each time the function "EntryPoint" is being called (it is repeatedly 
    # called over and over until failure). 

    # Data provider to create transform custom data from input bytes
    fdp = atheris.FuzzedDataProvider(input_data)

    # Create a random integer from the input bytes
    r2 = fdp.ConsumeIntInRange(rLow, rHigh)

    # This is the first function we'll be fuzzing
    # First two vars are random integers, and passing the data provider through
    FunctionToCover(r1, r2, fdp)

    return

@atheris.instrument_func
def FunctionToCover(input1, input2, fdp):

    # When both integers match, fall through and cover the "FinalFunctionCall"
    if input1 == input2:
        FinalFunctionCall(input1, fdp)
    return

@atheris.instrument_func
def FinalFunctionCall(intInput1, fdp):

    # Creating another random integer from the initial set of bytes for comparison
    r3 = fdp.ConsumeIntInRange(rLow, rHigh)

    # When the third random integer matches the first, we are done and have covered 
    # all the code. 
    if intInput1 == r3:
        raise RuntimeError("Found it!", intInput1, r3)
    return

atheris.Setup(sys.argv, EntryPoint)
atheris.Fuzz()