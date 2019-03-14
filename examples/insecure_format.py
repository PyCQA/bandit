
class Format:
    FORMAT_STR = 'Insecure cause Attr {}'

    def insecure_format(self, format_data):
        self.FORMAT_STR.format(format_data)  # Insecure

    @staticmethod
    def format_event(format_string, event):
        return format_string.format(event=event)  # Insecure

    @staticmethod
    def format_event_default(format_string, event=''):
        return format_string.format(event=event)  # Insecure


user_input = '{event.__init__.__globals__[CONFIG][SECRET_KEY]}'
user_input.format(event="Secure cause hard-code str")  # Secure

user_input = my_function("string format")
user_input.format(event="Secure cause hard-code str")  # Insecure

secure_contact = 'Secure'
secure_contact += '{}'
secure_contact.format("Secure")  # Secure

insecure_contact = 'InSecure {}'
insecure_contact += my_function("string format")
insecure_contact.format("Risk")  # Insecure

a, b = 'a', my_function("string format")
a.format("secure")  # Secure
b.format("insecure")  # Insecure

"This is {} way".format("secure")  # Secure
