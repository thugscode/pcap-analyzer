# PCAP Analyzer

A full-stack application for analyzing network packet capture (PCAP) files. The project consists of a C++ backend for efficient PCAP file processing and a React-based frontend for interactive data visualization.

## Features

### Backend (C++)
- High-performance PCAP file parsing using libpcap
- RESTful API endpoints using Crow framework
- Support for various network protocols (TCP, UDP, ICMP, DNS, HTTP)
- Comprehensive packet analysis including network layer information
- JSON output for frontend consumption

### Frontend (React)
- Interactive dashboard for visualizing packet data
- Real-time packet size analysis with Plotly.js
- Protocol distribution charts using Chart.js and Recharts
- Network topology visualization with Sigma.js and D3.js
- Packet detail view with comprehensive information
- File upload functionality for local PCAP analysis
- Responsive design with modern UI components

## Project Structure

```
pcap-analyzer/
├── backend/                    # C++ backend application
│   ├── CMakeLists.txt         # CMake build configuration
│   ├── main.cpp               # Main backend application
│   ├── build/                 # Build output directory
│   ├── external/              # External dependencies
│   │   ├── crow/              # Crow HTTP framework
│   │   └── json/              # nlohmann/json library
│   └── input/                 # Sample PCAP files
│       └── input.pcap
├── frontend/                  # React frontend application
│   ├── public/
│   │   ├── index.html         # Main HTML file
│   │   └── favicon.ico        # Application favicon
│   ├── src/
│   │   ├── components/        # React components
│   │   │   ├── Dashboard.jsx  # Main dashboard component
│   │   │   ├── FileUploader.jsx # File upload component
│   │   │   ├── Header.jsx     # Application header
│   │   │   ├── NetworkGraph.jsx # Network topology visualization
│   │   │   ├── PacketDetail.jsx # Detailed packet information
│   │   │   ├── PacketTable.jsx  # Packet data table
│   │   │   └── charts/        # Chart components
│   │   │       ├── NetworkGraph.jsx
│   │   │       ├── PacketSizeChart.jsx
│   │   │       ├── ProtocolDistribution.jsx
│   │   │       └── SizeHistogram.jsx
│   │   ├── services/          # API and data processing services
│   │   │   └── api.js
│   │   ├── hooks/             # Custom React hooks
│   │   │   └── usePacketData.js
│   │   ├── utils/             # Utility functions
│   │   │   └── formatters.js
│   │   ├── styles/            # CSS styles
│   │   │   ├── App.css
│   │   │   └── index.css
│   │   ├── App.jsx            # Main application component
│   │   └── index.jsx          # Entry point for React application
│   ├── package.json           # Frontend dependencies and scripts
│   └── jsconfig.json          # JavaScript project configuration
└── README.md                  # Project documentation
```

## Prerequisites

- **C++ Compiler**: GCC or Clang with C++17 support
- **CMake**: Version 3.10 or higher
- **libpcap**: For packet capture functionality
- **Node.js**: Version 14 or higher
- **npm**: For frontend dependency management

## Installation

### Backend Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/pcap-analyzer.git
   cd pcap-analyzer
   ```

2. Install system dependencies (Ubuntu/Debian):
   ```bash
   sudo apt-get update
   sudo apt-get install build-essential cmake libpcap-dev pkg-config
   ```

3. Build the backend:
   ```bash
   cd backend
   mkdir -p build
   cd build
   cmake ..
   make
   ```

### Frontend Setup

1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

## Usage

### Running the Backend

1. From the backend build directory:
   ```bash
   cd backend/build
   ./pcap_analyzer
   ```

The backend server will start on `http://localhost:8080` by default.

### Running the Frontend

1. From the frontend directory:
   ```bash
   npm start
   ```

The frontend development server will start on `http://localhost:3000`.

### Analyzing PCAP Files

1. Place your PCAP files in the `backend/input/` directory
2. Use the web interface to upload and analyze files
3. View the interactive visualizations and detailed packet information

## API Endpoints

The backend provides the following REST API endpoints:

- `GET /api/packets` - Retrieve all analyzed packets
- `GET /api/protocols` - Get protocol distribution data
- `GET /api/network-graph` - Get network topology data
- `POST /api/upload` - Upload PCAP files for analysis

## Technologies Used

### Backend
- **C++17**: Core programming language
- **libpcap**: Packet capture library
- **Crow**: Lightweight HTTP framework
- **nlohmann/json**: JSON parsing and generation
- **CMake**: Build system

### Frontend
- **React**: User interface framework
- **Chart.js**: Interactive charts
- **Plotly.js**: Advanced data visualization
- **Sigma.js**: Network graph visualization
- **D3.js**: Data-driven documents
- **Axios**: HTTP client for API communication
- **React Router**: Client-side routing

## Development

### Backend Development

- The backend is built using modern C++ practices
- External dependencies are managed through Git submodules
- The application uses a multi-threaded architecture for efficient packet processing

### Frontend Development

- Built with React functional components and hooks
- Uses modern JavaScript (ES6+) features
- Responsive design with CSS Grid and Flexbox
- Component-based architecture for maintainability

### Building for Production

#### Backend
```bash
cd backend/build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
```

#### Frontend
```bash
cd frontend
npm run build
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Acknowledgments

- libpcap community for the excellent packet capture library
- Crow framework for the lightweight HTTP server implementation
- React community for the robust frontend framework
- Chart.js, Plotly.js, and Sigma.js for visualization capabilities