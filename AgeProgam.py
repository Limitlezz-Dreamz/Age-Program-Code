# First, ask the user for the age and store it in the `age` variable.
# This variable is a string, because the input() method always returns a string.
age = input('Enter your age: ')

# Then, print out the information to the user.
# Here we use the format() method to replace each pair of curly braces
#       for each argument of the format() method (separated by commas).
print("You have lived for {} seconds. This corresponds to {} years.".format(int(age) * 365 * 24 * 60 * 60, age))
