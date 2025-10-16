import tkinter as tk
from tkinter import ttk

class MyApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Multi-Page Tkinter App")

        # 1) Create a container for all “pages”
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True)

        # 2) Make a dict to hold page instances
        self.frames = {}

        # 3) Instantiate each “page” and stack them
        for PageClass in (HomePage, SettingsPage, AboutPage):
            page = PageClass(container, self)
            self.frames[PageClass.__name__] = page
            page.grid(row=0, column=0, sticky="nsew")

        # 4) Show the “HomePage” first
        self.show_frame("HomePage")

    def show_frame(self, page_name):
        """Raise the requested frame/page to the top."""
        frame = self.frames[page_name]
        frame.tkraise()


class HomePage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        ttk.Label(self, text="🏠 Home Page", font=("Segoe UI", 18)).pack(pady=20)

        ttk.Button(self, text="Go to Settings",
                   command=lambda: controller.show_frame("SettingsPage")).pack(pady=10)
        ttk.Button(self, text="Go to About",
                   command=lambda: controller.show_frame("AboutPage")).pack(pady=10)


class SettingsPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        ttk.Label(self, text="⚙ Settings", font=("Segoe UI", 18)).pack(pady=20)

        # “Back” button takes you to HomePage
        ttk.Button(self, text="← Back to Home",
                   command=lambda: controller.show_frame("HomePage")).pack(pady=10)


class AboutPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        ttk.Label(self, text="ℹ About This App", font=("Segoe UI", 18)).pack(pady=20)

        # “Back” button also returns to HomePage
        ttk.Button(self, text="← Back to Home",
                   command=lambda: controller.show_frame("HomePage")).pack(pady=10)


if __name__ == "__main__":
    app = MyApp()
    app.mainloop()
