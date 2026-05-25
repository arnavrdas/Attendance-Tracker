BLUE='\e[34m'
NC='\e[0m' # No Color

echo -e  "${BLUE}Moving to root directory...${NC}"
cd /var/www/html/office/Attendance-Tracker/

echo -e "${BLUE}Deleting previous /venv & /__pycache__${NC}"
rm -R venv __pycache__

echo -e "${BLUE}Creating venv...${NC}"
python3 -m venv venv

echo -e "${BLUE}Activating venv...${NC}"
source venv/bin/activate

echo -e "${BLUE}Installing requirements...${NC}"
pip install -r requirements.txt

echo -e "${BLUE}Updating requirements...${NC}"
pip freeze > requirements.txt

echo -e "${BLUE}Starting Uvicorn...${NC}"
uvicorn main:app --reload --port 8000