# Use Rocky Linux 9 as the base image
FROM rockylinux:9

# Set working directory
WORKDIR /opt/threat-overview-dashboard-demo

# Install dependencies
RUN dnf -y update
RUN dnf -y install epel-release
RUN dnf -y install supervisor

# Copy files and directories
COPY dashboard /opt/threat-overview-dashboard-demo/dashboard
COPY install.sh /opt/threat-overview-dashboard-demo/install.sh
COPY supervisord.conf /opt/threat-overview-dashboard-demo/supervisord.conf

# Make the install script executable
RUN chmod +x /opt/threat-overview-dashboard-demo/install.sh

# Run the install script
RUN /opt/threat-overview-dashboard-demo/install.sh

# Expose the port that the application will use
EXPOSE 5000

# Expose the port for the supervisord control interface
EXPOSE 9001

# Start supervisord
CMD ["/usr/bin/supervisord", "-c", "/opt/threat-overview-dashboard-demo/supervisord.conf"]

