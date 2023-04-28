import sys
import matplotlib.pyplot as plt

from data.trace import Trace
from utils.utils import Utils


class Plotter:

    def __init__(self) -> None:
        self.speed_time_values = []
        self.speed_values = []
        self.revolution_time_value = []
        self.revolution_values = []
        self.logger = Utils.get_logger()

    def plot_speed_signal(self, trace: Trace, file_name):
        # get speed signal
        if len(self.speed_values) == 0:
            self.speed_time_values, self.speed_values = trace.get_speed_signal()

        plt.figure(0)
        plt.plot(self.speed_time_values, self.speed_values, "bo", markersize=2)
        axes = plt.gca()
        plt.savefig(file_name + ".pdf")
        plt.savefig(file_name + ".png", dpi=300)
        plt.clf()

    def plot_revolution_signal(self, trace: Trace, file_name):
        # get revolution signal
        if len(self.revolution_values) == 0:
            self.revolution_time_value, self.revolution_values = trace.get_revolution_signal()

        plt.figure(0)
        plt.plot(self.revolution_time_value,
                 self.revolution_values, "bo", markersize=2)
        axes = plt.gca()
        plt.savefig(file_name + ".pdf")
        plt.savefig(file_name + ".png", dpi=300)
        plt.clf()

    def plot_both_signals(self, trace: Trace, file_name):
        self.speed_time_values, self.speed_values = trace.get_speed_signal()
        self.revolution_time_value, self.revolution_values = trace.get_revolution_signal()

        if self.speed_time_values is None or self.speed_values is None or self.revolution_time_value is None or self.revolution_values is None:
            self.logger.error(f"Stopping plotting due to signal interpretation error in file: {file_name}")
            sys.exit(-1)

        fig, ax1 = plt.subplots()

        color = 'tab:blue'
        ax1.set_xlabel('time (s)')
        ax1.set_ylabel('Engine revolution (1/min)', color=color)
        ax1.plot(self.revolution_time_value, self.revolution_values, '.', markersize=2, color=color)
        ax1.tick_params(axis='y', labelcolor=color)

        ax2 = ax1.twinx()  # instantiate a second axes that shares the same x-axis

        color = 'tab:red'
        # we already handled the x-label with ax1
        ax2.set_ylabel('Vehicle speed (km/h)', color=color)
        ax2.plot(self.speed_time_values, self.speed_values, '.r', markersize=2)
        ax2.tick_params(axis='y', labelcolor=color)

        fig.tight_layout()  # otherwise the right y-label is slightly clipped

        # add start and end lines for malicious traces
        if trace.first_attack_time is not None and trace.last_attack_time is not None:
            plt.axvline(x=trace.first_attack_time, linestyle='dashed', linewidth=1, color='orange')
            plt.axvline(x=trace.last_attack_time, linestyle='dashed', linewidth=1, color='orange')

        plt.savefig(file_name + ".pdf")
        plt.savefig(file_name + ".png", dpi=300)
        plt.close()
