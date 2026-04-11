#!/bin/bash
# ============================================
# VulnOps CVE Registry - EC2 Setup Script
# Run this script on a fresh Ubuntu EC2 instance
# ============================================

set -e

echo "Setting up VulnOps CVE Registry..."
echo "==========================================="

# Update system packages
echo "Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install Node.js 20.x
echo "Installing Node.js 20.x..."
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

echo "Node.js version: $(node -v)"
echo "npm version: $(npm -v)"

# Install PostgreSQL
echo "Installing PostgreSQL..."
sudo apt install -y postgresql postgresql-contrib

# Install Nginx
echo "Installing Nginx..."
sudo apt install -y nginx

# Install PM2
echo "Installing PM2..."
sudo npm install -g pm2

# Configure PostgreSQL
echo "Configuring PostgreSQL..."
sudo -u postgres psql <<EOF
CREATE USER vulnops WITH PASSWORD 'vulnops_pass_2026';
CREATE DATABASE vulnops OWNER vulnops;
GRANT ALL PRIVILEGES ON DATABASE vulnops TO vulnops;
\c vulnops
GRANT ALL ON SCHEMA public TO vulnops;
EOF

echo "PostgreSQL configured"

# Set up project directory
echo "Setting up project directory..."
sudo mkdir -p /var/www/vulnops
sudo chown -R $USER:$USER /var/www/vulnops

# Copy project files (assumes source is at ~/VulnOps)
cp -r ~/VulnOps/* /var/www/vulnops/

# Create backend .env
echo "Creating backend environment config..."
cat > /var/www/vulnops/backend/.env <<EOF
DB_USER=vulnops
DB_PASSWORD=vulnops_pass_2026
DB_HOST=localhost
DB_PORT=5432
DB_NAME=vulnops
PORT=5000
EOF

# Install backend dependencies
# --ignore-scripts blocks malicious postinstall hooks from executing during package installation.
# Axios versions 1.14.1 and 0.30.4 were compromised via a supply chain attack that used a
# postinstall hook to drop a plain-crypto-js RAT payload on the host. --ignore-scripts
# mitigates this class of attack. If any package legitimately requires postinstall scripts,
# run them explicitly and audit them first.
echo "Installing backend dependencies..."
cd /var/www/vulnops/backend
npm install --production --ignore-scripts

# Build frontend
echo "Building frontend..."
cd /var/www/vulnops/frontend
npm install --ignore-scripts
npm run build

# Configure Nginx
echo "Configuring Nginx..."
sudo cp /var/www/vulnops/deploy/vulnops-nginx.conf /etc/nginx/sites-available/vulnops
sudo ln -sf /etc/nginx/sites-available/vulnops /etc/nginx/sites-enabled/vulnops
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl restart nginx
sudo systemctl enable nginx

# Start backend with PM2
echo "Starting backend with PM2..."
cd /var/www/vulnops/backend
pm2 start src/index.js --name vulnops-backend
pm2 save
pm2 startup systemd -u $USER --hp /home/$USER | tail -1 | sudo bash

echo ""
echo "==========================================="
echo "VulnOps is now live!"
echo "==========================================="
echo ""
echo "Access VulnOps at: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo '<your-ec2-public-ip>')"
echo ""
echo "Useful commands:"
echo "  pm2 status                   - Check backend status"
echo "  pm2 logs                     - View backend logs"
echo "  pm2 restart all              - Restart backend"
echo "  sudo systemctl restart nginx - Restart Nginx"
echo ""
