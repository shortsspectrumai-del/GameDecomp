// Original, trusted fixture. Tests compile this file; they never execute it.
namespace Game {
enum class Kind : unsigned short { Actor = 3, Camera = 9 };
struct Node { int value; Node* next; };
struct Flags { unsigned bits : 3; signed code : 5; const Node* const owner; volatile unsigned counter; };
union Scalar { int integer; float real; };
template <typename T> struct Holder { T value; };
class Actor {
public:
    int health;
    virtual ~Actor();
    virtual int update(int ticks) const;
};
class Moving : public Actor {
public:
    float speed;
    int update(int ticks) const override;
};
class Drawable { public: virtual ~Drawable(); virtual void draw(); };
class Entity : public Moving, public Drawable {
public:
    Node* node;
    Flags* flags;
    Kind kind;
    Scalar scalar;
    int samples[3];
    Holder<int> holder;
    int update(int ticks) const override;
};
class VirtualEntity : public virtual Actor { public: int flags; };
Actor::~Actor() = default;
int Actor::update(int ticks) const { return health + ticks; }
int Moving::update(int ticks) const { return health + ticks + static_cast<int>(speed); }
Drawable::~Drawable() = default;
void Drawable::draw() {}
int Entity::update(int ticks) const { return health + ticks + holder.value; }
}
extern "C" int game_update(Game::Entity* entity, int ticks) {
    return entity->update(ticks);
}
extern "C" void* game_virtual() { return new Game::VirtualEntity; }
