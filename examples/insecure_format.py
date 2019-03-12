
class Format:
    FORMAT_STR = 'Insecure cause Attr {}'

    def insecure_format(self, format_data):
        self.FORMAT_STR.format(format_data)

    @staticmethod
    def format_event(format_string, event):
        return format_string.format(event=event)  # Insecure


user_input = '{event.__init__.__globals__[CONFIG][SECRET_KEY]}'
user_input.format(event="Secure cause hard-code str")

user_input = input("string format")
user_input.format(event="Secure cause hard-code str")


"This is {} way".format("secure")
